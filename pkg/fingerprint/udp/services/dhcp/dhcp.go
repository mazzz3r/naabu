// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package dhcp

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects DHCP servers (port 67) with a DISCOVER message and parses the
// returned option set. DHCP only answers requests from source port 67, so the
// plugin declares SrcPort and the engine binds it (requires privilege).
type Plugin struct{}

func (Plugin) Name() string          { return "dhcp" }
func (Plugin) Ports() []uint16       { return []uint16{67} }
func (Plugin) Priority() int         { return 100 }
func (Plugin) SrcPort() uint16       { return 67 }
func (Plugin) Payload(uint16) []byte { return nil } // DISCOVER carries a random XID/MAC

func getSignatures() map[int]string {
	signature := map[int]string{
		0:   "Pad",
		1:   "Subnet Mask",
		2:   "Time Offset",
		3:   "Router",
		4:   "Time Server",
		5:   "Name Server",
		6:   "Domain Server",
		7:   "Log Server",
		8:   "Quotes Server",
		9:   "LPR Server",
		10:  "Impress Server",
		11:  "RLP Server",
		12:  "Hostname",
		13:  "Boot File Size",
		14:  "Merit Dump File",
		15:  "Domain Name",
		16:  "Swap Server",
		17:  "Root Path",
		18:  "Extension File",
		19:  "Forward On/Off",
		20:  "SrcRte On/Off",
		21:  "Policy Filter",
		22:  "Max DG Assembly",
		23:  "Default IP TTL",
		24:  "MTU Timeout",
		25:  "MTU Plateau",
		26:  "MTU Interface",
		27:  "MTU Subnet",
		28:  "Broadcast Address",
		29:  "Mask Discovery",
		30:  "Mask Supplier",
		31:  "Router Discovery",
		32:  "Router Request",
		33:  "Static Route",
		34:  "Trailers",
		35:  "ARP Timeout",
		36:  "Ethernet",
		37:  "Default TCP TTL",
		38:  "Keepalive Time",
		39:  "Keepalive Data",
		40:  "NIS Domain",
		41:  "NIS Servers",
		42:  "NTP Servers",
		43:  "Vendor Specific",
		44:  "NETBIOS Name Srv",
		45:  "NETBIOS Dist Srv",
		46:  "NETBIOS Node Type",
		47:  "NETBIOS Scope",
		48:  "X Window Font",
		49:  "X Window Manager",
		50:  "Address Request",
		51:  "Address Time",
		52:  "Overload",
		53:  "DHCP Msg Type",
		54:  "DHCP Server Id",
		55:  "Parameter List",
		56:  "DHCP Message",
		57:  "DHCP Max Msg Size",
		58:  "Renewal Time",
		59:  "Rebinding Time",
		60:  "Class Id",
		61:  "Client Id",
		62:  "NetWare/IP Domain",
		63:  "NetWare/IP Option",
		64:  "NIS-Domain-Name",
		65:  "NIS-Server-Addr",
		66:  "Server-Name",
		67:  "Bootfile-Name",
		68:  "Home-Agent-Addrs",
		69:  "SMTP-Server",
		70:  "POP3-Server",
		71:  "NNTP-Server",
		72:  "WWW-Server",
		73:  "Finger-Server",
		74:  "IRC-Server",
		75:  "StreetTalk-Server",
		76:  "STDA-Server",
		77:  "User-Class",
		78:  "Directory Agent",
		79:  "Service Scope",
		80:  "Rapid Commit",
		81:  "Client FQDN",
		82:  "Relay Agent Information",
		83:  "iSNS",
		85:  "NDS Servers",
		86:  "NDS Tree Name",
		87:  "NDS Context",
		88:  "BCMCS Controller Domain Name list",
		89:  "BCMCS Controller IPv4 address option",
		90:  "Authentication",
		91:  "client-last-transaction-time option",
		92:  "associated-ip option",
		93:  "Client System",
		94:  "Client NDI",
		95:  "LDAP",
		97:  "UUID/GUID",
		98:  "User-Auth",
		99:  "GEOCONF_CIVIC",
		100: "PCode",
		101: "TCode",
		109: "OPTION_DHCP4O6_S46_SADDR",
		112: "Netinfo Address",
		113: "Netinfo Tag",
		114: "URL",
		116: "Auto-Config",
		117: "Name Service Search",
		118: "Subnet Selection Option",
		119: "Domain Search",
		120: "SIP Servers DHCP Option",
		121: "Classless",
		122: "CCC",
		123: "GeoConf Option",
		124: "V-I Vendor",
		125: "V-I Vendor-Specific Information",
		131: "Remote statistics server IP address",
		132: "IEEE 802.1Q VLAN ID",
		133: "IEEE 802.1D/p Layer",
		134: "Diffserv Code Point",
		135: "HTTP Proxy for phone-specific applications",
		136: "OPTION_PANA_AGENT",
		137: "OPTION_V4_LOST",
		138: "OPTION_CAPWAP_AC_V4",
		139: "OPTION-IPv4_Address-MoS",
		140: "OPTION-IPv4_FQDN-MoS",
		141: "SIP UA Configuration Service Domains",
		142: "OPTION-IPv4_Address-ANDSF",
		143: "OPTION_V4_SZTP_REDIRECT",
		144: "GeoLoc",
		145: "FORCERENEW_NONCE_CAPABLE",
		146: "RDNSS Selection",
		151: "status-code",
		152: "base-time",
		153: "start-time-of-state",
		154: "query-start-time",
		155: "query-end-time",
		156: "dhcp-state",
		157: "data-source",
		158: "OPTION_V4_PCP_SERVER",
		160: "DHCP Captive-Portal",
		161: "OPTION_MUD_URL_V4",
		175: "Etherboot",
		176: "IP Telephone",
		209: "Configuration File",
		210: "Path Prefix",
		211: "Reboot Time",
		212: "OPTION_6RD",
		213: "OPTION_V4_ACCESS_DOMAIN",
		220: "Subnet Allocation Option",
		221: "Virtual Subnet Selection",
		255: "End",
	}
	return signature
}

func hostnameParse(options []byte) []string {
	var ret string
	var retList []string

	// Bounds check before slicing with network-controlled length
	optLen := int(options[1])
	if len(options) < optLen+2 {
		return retList
	}
	wholePacket := options[2 : 2+optLen]
	packet := wholePacket

	for len(packet) != 0 {
		length := int(packet[0])
		if len(packet) < length+1 {
			return retList
		}
		if length == 0 {
			retList = append(retList, ret)
			ret = ""
			packet = packet[1:]
		} else {
			ret += string(packet[1 : 1+length])
			packet = packet[1+length:]
			if len(packet) == 0 {
				break
			}
			if packet[0] != 0 {
				ret += "."
			}
			if packet[0] == 0xc0 && len(packet) == 2 {
				// Validate compression pointer bounds
				compressionOffset := int(packet[1])
				endOffset := 4 + length
				if compressionOffset >= len(wholePacket) || endOffset > len(wholePacket) {
					return retList
				}
				wholePacket = wholePacket[compressionOffset : len(wholePacket)-endOffset]
				packet = wholePacket
			}
		}
	}
	retList = append(retList, ret)
	return retList
}

func ipParse(options []byte) []string {
	var ipStrList []string

	// Bounds check before slicing with network-controlled length
	optLen := int(options[1])
	if len(options) < optLen+2 {
		return ipStrList
	}

	ipLen := optLen / 4
	ipList := options[2 : 2+optLen]

	for ipLen != 0 {
		// Ensure we have at least 4 bytes for a full IP address
		if len(ipList) < 4 {
			return ipStrList
		}
		ip := fmt.Sprintf("%d.%d.%d.%d", int(ipList[0]), int(ipList[1]), int(ipList[2]), int(ipList[3]))
		ipStrList = append(ipStrList, ip)
		ipLen--
		ipList = ipList[4:]
	}
	return ipStrList
}

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	sliceIP := net.ParseIP("127.0.0.1")
	if sliceIP == nil {
		return nil, &udp.InvalidAddrProvided{Service: "dhcp"}
	}
	localIP := []byte{sliceIP[12], sliceIP[13], sliceIP[14], sliceIP[15]}

	discover := []byte{
		0x01, // Boot Request
		0x01, // Hardware type: Ethernet
		0x06, // Hardware address length
		0x01, // Hops
	}
	transactionID := make([]byte, 4)
	if _, err := rand.Read(transactionID); err != nil {
		return nil, &udp.RandomizeError{Message: "transaction ID"}
	}
	discover = append(discover, transactionID...)
	discover = append(discover,
		0x00, 0x00, // Seconds elapsed
		0x00, 0x00, // Bootp flags: Unicast
		0x00, 0x00, 0x00, 0x00, // Client IP
		0x00, 0x00, 0x00, 0x00, // Your IP
		0x00, 0x00, 0x00, 0x00, // Next server IP
	)
	discover = append(discover, localIP...) // Relay agent IP
	clientMAC := make([]byte, 6)
	if _, err := rand.Read(clientMAC); err != nil {
		return nil, &udp.RandomizeError{Message: "client MAC"}
	}
	discover = append(discover, clientMAC...)
	// Client hardware address padding (10) + server host name (64) + boot file (128).
	discover = append(discover, make([]byte, 10+64+128)...)
	discover = append(discover,
		0x63, 0x82, 0x53, 0x63, // Magic cookie
		0x35, 0x01, 0x01, // Option 53: DHCP Message Type = DISCOVER
		0xff, // Option 255: End
	)

	response, err := udp.SendRecv(conn, discover, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 8 || !bytes.Equal(transactionID, response[4:8]) {
		return nil, nil
	}
	if len(response) <= 240 || response[len(response)-1] != 0xff {
		return nil, nil
	}

	signature := getSignatures()
	options := response[240:]
	optionList := map[string]any{}
	for len(options) > 0 && int(options[0]) != 255 {
		if len(options) < 2 || len(options) < int(options[1])+2 {
			break
		}
		code := int(options[0])
		optLen := int(options[1])
		switch code {
		case 51, 58, 59:
			optionList[signature[code]] = big.NewInt(0).SetBytes(options[2 : 2+optLen]).Uint64()
		case 119:
			optionList[signature[code]] = hostnameParse(options)
		case 15:
			optionList[signature[code]] = string(options[2 : 2+optLen])
		case 1:
			ipStrList := ipParse(options)
			if len(ipStrList) == 1 {
				optionList[signature[code]] = ipStrList[0]
			} else {
				optionList[signature[code]] = ipStrList
			}
		case 3, 6, 28, 42, 44, 54:
			optionList[signature[code]] = ipParse(options)
		default:
			if optLen == 1 {
				optionList[signature[code]] = int(options[2])
			} else {
				optionList[signature[code]] = options[2 : 2+optLen]
			}
		}
		options = options[2+optLen:]
	}

	return &udp.Result{Name: "dhcp", ExtraInfo: fmt.Sprintf("options=%s", optionList)}, nil
}
