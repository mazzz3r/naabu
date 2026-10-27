// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package knxip

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects KNXnet/IP building-automation gateways (port 3671) with a
// Search Request and parses the device name, KNX address and supported service
// families from the Search Response.
type Plugin struct{}

const (
	headerLength          = 0x06
	protocolVer           = 0x10
	searchResponse uint16 = 0x0202
	dibDevInfo            = 0x01
	dibSuppSvc            = 0x02
)

// searchRequest is a KNXnet/IP Search Request with a 0.0.0.0:0 discovery HPAI.
var searchRequest = []byte{
	headerLength, protocolVer,
	0x02, 0x01, // Service type: Search Request
	0x00, 0x0E, // Total length
	0x08, 0x01, // HPAI length, UDP
	0x00, 0x00, 0x00, 0x00, // IP 0.0.0.0
	0x00, 0x00, // Port 0
}

func (Plugin) Name() string          { return "knxip" }
func (Plugin) Ports() []uint16       { return []uint16{3671} }
func (Plugin) Priority() int         { return 400 }
func (Plugin) Payload(uint16) []byte { return searchRequest }

// device holds the fields parsed out of a KNX Search Response.
type device struct {
	Name     string
	Address  string
	Serial   string
	MAC      string
	Medium   string
	Families []string
}

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	response, err := udp.SendRecv(conn, searchRequest, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 8 || response[0] != headerLength || response[1] != protocolVer {
		return nil, nil
	}
	if binary.BigEndian.Uint16(response[2:4]) != searchResponse {
		return nil, nil
	}
	totalLength := int(binary.BigEndian.Uint16(response[4:6]))
	if totalLength < headerLength || totalLength > len(response) {
		return nil, nil
	}

	dev := parseSearchResponse(response[:totalLength])
	var extra []string
	if dev.Address != "" {
		extra = append(extra, "knx_address="+dev.Address)
	}
	if dev.Medium != "" {
		extra = append(extra, "medium="+dev.Medium)
	}
	if dev.MAC != "" {
		extra = append(extra, "mac="+dev.MAC)
	}
	if len(dev.Families) > 0 {
		extra = append(extra, "services="+strings.Join(dev.Families, ","))
	}
	return &udp.Result{Name: "knxip", Product: dev.Name, ExtraInfo: strings.Join(extra, " ")}, nil
}

// parseSearchResponse walks the DIB structures of a Search Response.
func parseSearchResponse(data []byte) device {
	var dev device
	offset := 14 // header (6) + control endpoint HPAI (8)
	for offset+2 <= len(data) {
		dibLen := int(data[offset])
		dibType := data[offset+1]
		if dibLen == 0 || offset+dibLen > len(data) {
			break
		}
		switch dibType {
		case dibDevInfo:
			parseDeviceInfo(data[offset:offset+dibLen], &dev)
		case dibSuppSvc:
			parseServiceFamilies(data[offset:offset+dibLen], &dev)
		}
		offset += dibLen
	}
	return dev
}

func parseDeviceInfo(dib []byte, dev *device) {
	if len(dib) < 54 {
		return
	}
	dev.Medium = knxMediumString(dib[2])
	addr := binary.BigEndian.Uint16(dib[4:6])
	dev.Address = fmt.Sprintf("%d.%d.%d", (addr>>12)&0xF, (addr>>8)&0xF, addr&0xFF)
	dev.Serial = hex.EncodeToString(dib[8:14])
	dev.MAC = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", dib[18], dib[19], dib[20], dib[21], dib[22], dib[23])
	dev.Name = strings.TrimRight(string(dib[24:54]), "\x00 ")
}

func parseServiceFamilies(dib []byte, dev *device) {
	if len(dib) < 4 {
		return
	}
	for i := 2; i+1 < len(dib); i += 2 {
		if name := serviceFamilyName(dib[i]); name != "" {
			dev.Families = append(dev.Families, name)
		}
	}
}

func knxMediumString(code byte) string {
	switch code {
	case 0x01:
		return "TP1"
	case 0x02:
		return "PL110"
	case 0x04:
		return "RF"
	case 0x20:
		return "IP"
	default:
		return fmt.Sprintf("0x%02X", code)
	}
}

func serviceFamilyName(id byte) string {
	switch id {
	case 0x02:
		return "Core"
	case 0x03:
		return "DeviceManagement"
	case 0x04:
		return "Tunnelling"
	case 0x05:
		return "Routing"
	case 0x06:
		return "RemoteLogging"
	case 0x08:
		return "ObjectServer"
	default:
		return ""
	}
}
