// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package netbios

import (
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects the NetBIOS Name Service (RFC 1002, port 137) with an NBSTAT
// Node Status Request for the wildcard name and parses the name table and MAC
// address out of the reply.
type Plugin struct{}

// query is the NBSTAT request body after the 2-byte transaction ID.
var query = []byte{
	0x00, 0x00, // Flags: standard query
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
	0x00, 0x21, // QTYPE: NBSTAT
	0x00, 0x01, // QCLASS: IN
}

func (Plugin) Name() string          { return "netbios-ns" }
func (Plugin) Ports() []uint16       { return []uint16{137} }
func (Plugin) Priority() int         { return 700 }
func (Plugin) Payload(uint16) []byte { return append([]byte{0x13, 0x37}, query...) }

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	transactionID := make([]byte, 2)
	if _, err := rand.Read(transactionID); err != nil {
		return nil, &udp.RandomizeError{Message: "transaction ID"}
	}
	probe := append(append([]byte{}, transactionID...), query...)

	response, err := udp.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 2 || response[0] != transactionID[0] || response[1] != transactionID[1] {
		return nil, nil
	}

	name, group, mac, ok := parseNBSTATResponse(response)
	if !ok {
		return nil, nil
	}
	var extra []string
	if group != "" {
		extra = append(extra, "group="+group)
	}
	if mac != "" {
		extra = append(extra, "mac="+mac)
	}
	return &udp.Result{Name: "netbios-ns", Product: name, ExtraInfo: strings.Join(extra, " ")}, nil
}

// parseNBSTATResponse parses an NBSTAT Node Status response (RFC 1002) and
// returns the workstation name, workgroup/domain name and MAC address.
func parseNBSTATResponse(data []byte) (name, group, mac string, ok bool) {
	if len(data) < 12 {
		return "", "", "", false
	}
	flags := (uint16(data[2]) << 8) | uint16(data[3])
	if flags&0x8000 == 0 || flags&0x000F != 0 {
		return "", "", "", false
	}
	if answerCount := (uint16(data[6]) << 8) | uint16(data[7]); answerCount == 0 {
		return "", "", "", false
	}

	offset := skipDNSName(data, 12)
	if offset < 0 || offset+4 > len(data) {
		return "", "", "", false
	}
	offset += 4 // QTYPE + QCLASS

	offset = skipDNSName(data, offset)
	if offset < 0 || offset+10 > len(data) {
		return "", "", "", false
	}
	rrType := (uint16(data[offset]) << 8) | uint16(data[offset+1])
	rrClass := (uint16(data[offset+2]) << 8) | uint16(data[offset+3])
	if rrType != 0x0021 || rrClass != 0x0001 {
		return "", "", "", false
	}
	rdLength := int((uint16(data[offset+8]) << 8) | uint16(data[offset+9]))
	offset += 10
	if offset+rdLength > len(data) {
		return "", "", "", false
	}
	rdataEnd := offset + rdLength
	if offset >= rdataEnd {
		return "", "", "", false
	}
	numNames := int(data[offset])
	offset++

	const nameEntryLen = 18
	if offset+numNames*nameEntryLen > rdataEnd {
		return "", "", "", false
	}

	for i := 0; i < numNames; i++ {
		entryOffset := offset + i*nameEntryLen
		entryName := strings.TrimRight(string(data[entryOffset:entryOffset+15]), " \x00")
		suffix := data[entryOffset+15]
		nameFlags := (uint16(data[entryOffset+16]) << 8) | uint16(data[entryOffset+17])
		isGroup := nameFlags&0x8000 != 0

		if suffix == 0x00 && !isGroup && name == "" {
			name = entryName
		}
		if suffix == 0x00 && isGroup && group == "" {
			group = entryName
		}
	}

	if macOffset := offset + numNames*nameEntryLen; macOffset+6 <= rdataEnd {
		m := data[macOffset : macOffset+6]
		mac = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
	}

	if name == "" && numNames == 0 {
		return "", "", "", false
	}
	return name, group, mac, true
}

// skipDNSName advances past a DNS-encoded name, handling literal labels and
// compression pointers (RFC 1035 §4.1.4). Returns -1 on malformed data.
func skipDNSName(data []byte, offset int) int {
	if offset >= len(data) {
		return -1
	}
	if data[offset]&0xC0 == 0xC0 {
		if offset+2 > len(data) {
			return -1
		}
		return offset + 2
	}
	for offset < len(data) {
		labelLen := int(data[offset])
		if labelLen == 0 {
			return offset + 1
		}
		if labelLen&0xC0 == 0xC0 {
			if offset+2 > len(data) {
				return -1
			}
			return offset + 2
		}
		offset += labelLen + 1
	}
	return -1
}
