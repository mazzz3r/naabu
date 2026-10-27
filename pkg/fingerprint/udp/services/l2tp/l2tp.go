// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package l2tp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects L2TP (RFC 2661, port 1701) by sending a
// Start-Control-Connection-Request (SCCRQ) and parsing the SCCRP reply for the
// host name, vendor and protocol version.
type Plugin struct{}

const (
	avpMessageType      = 0
	avpProtocolVersion  = 2
	avpFirmwareRevision = 6
	avpHostName         = 7
	avpVendorName       = 8
	avpAssignedTunnelID = 9
	avpReceiveWindow    = 10
	msgSCCRQ            = 1
	msgSCCRP            = 2
)

func (Plugin) Name() string          { return "l2tp" }
func (Plugin) Ports() []uint16       { return []uint16{1701} }
func (Plugin) Priority() int         { return 200 }
func (Plugin) Payload(uint16) []byte { p, _ := buildSCCRQ([]byte{0x13, 0x37}); return p }

// buildSCCRQ builds an L2TP SCCRQ with the given assigned tunnel ID.
func buildSCCRQ(tunnelID []byte) ([]byte, []byte) {
	var packet bytes.Buffer
	_ = binary.Write(&packet, binary.BigEndian, uint16(0xC802)) // T=1,L=1,S=1,Ver=2
	lengthPos := packet.Len()
	_ = binary.Write(&packet, binary.BigEndian, uint16(0)) // length placeholder
	_ = binary.Write(&packet, binary.BigEndian, uint16(0)) // tunnel ID
	_ = binary.Write(&packet, binary.BigEndian, uint16(0)) // session ID
	_ = binary.Write(&packet, binary.BigEndian, uint16(0)) // Ns
	_ = binary.Write(&packet, binary.BigEndian, uint16(0)) // Nr

	packet.Write(buildAVP(avpMessageType, []byte{0, msgSCCRQ}))
	packet.Write(buildAVP(avpProtocolVersion, []byte{0x01, 0x00, 0x01, 0x00}))
	packet.Write(buildAVP(avpHostName, []byte("naabu")))
	packet.Write(buildAVP(avpAssignedTunnelID, tunnelID))
	windowSize := make([]byte, 2)
	binary.BigEndian.PutUint16(windowSize, 4)
	packet.Write(buildAVP(avpReceiveWindow, windowSize))

	out := packet.Bytes()
	binary.BigEndian.PutUint16(out[lengthPos:], uint16(len(out)))
	return out, tunnelID
}

// buildAVP builds a single mandatory IETF AVP.
func buildAVP(avpType uint16, value []byte) []byte {
	var avp bytes.Buffer
	_ = binary.Write(&avp, binary.BigEndian, uint16(len(value)+6)|0x8000) // length + mandatory bit
	_ = binary.Write(&avp, binary.BigEndian, uint16(0))                   // vendor ID: IETF
	_ = binary.Write(&avp, binary.BigEndian, avpType)
	avp.Write(value)
	return avp.Bytes()
}

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	tunnelID := make([]byte, 2)
	if _, err := rand.Read(tunnelID); err != nil {
		return nil, &udp.RandomizeError{Message: "tunnel ID"}
	}
	probe, _ := buildSCCRQ(tunnelID)

	response, err := udp.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	return parseResponse(response), nil
}

// parseResponse validates an L2TP SCCRP control message and extracts metadata.
func parseResponse(data []byte) *udp.Result {
	if len(data) < 12 {
		return nil
	}
	flags := binary.BigEndian.Uint16(data[0:2])
	if flags&0x8000 == 0 || flags&0x000F != 2 { // T bit set, version 2
		return nil
	}

	offset := 2
	length := uint16(len(data))
	if flags&0x4000 != 0 { // L bit: length present
		if len(data) < offset+2 {
			return nil
		}
		length = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		if int(length) > len(data) || int(length) < 12 {
			return nil
		}
	}
	offset += 4 // tunnel ID + session ID
	if flags&0x0800 != 0 {
		offset += 4 // Ns + Nr
	}
	if offset > len(data) || offset > int(length) {
		return nil
	}

	avps := data[offset:length]
	var messageType, firmware, assignedTunnel uint16
	var hostname, vendor, protocol string

	for count := 0; len(avps) >= 6 && count < 100; count++ {
		avpFlags := binary.BigEndian.Uint16(avps[0:2])
		avpLength := avpFlags & 0x03FF
		if avpLength < 6 || int(avpLength) > len(avps) {
			break
		}
		if binary.BigEndian.Uint16(avps[2:4]) != 0 { // skip vendor-specific
			avps = avps[avpLength:]
			continue
		}
		avpType := binary.BigEndian.Uint16(avps[4:6])
		value := avps[6:avpLength]
		switch avpType {
		case avpMessageType:
			if len(value) >= 2 {
				messageType = binary.BigEndian.Uint16(value)
			}
		case avpProtocolVersion:
			if len(value) >= 2 {
				protocol = fmt.Sprintf("%d.%d", value[0], value[1])
			}
		case avpHostName:
			hostname = sanitizeString(string(value))
		case avpVendorName:
			vendor = sanitizeString(string(value))
		case avpFirmwareRevision:
			if len(value) >= 2 {
				firmware = binary.BigEndian.Uint16(value)
			}
		case avpAssignedTunnelID:
			if len(value) >= 2 {
				assignedTunnel = binary.BigEndian.Uint16(value)
			}
		}
		avps = avps[avpLength:]
	}

	if messageType != msgSCCRP {
		return nil
	}

	var extra []string
	if hostname != "" {
		extra = append(extra, "host="+hostname)
	}
	if firmware != 0 {
		extra = append(extra, fmt.Sprintf("firmware=%d", firmware))
	}
	if assignedTunnel != 0 {
		extra = append(extra, fmt.Sprintf("tunnel_id=%d", assignedTunnel))
	}
	return &udp.Result{Name: "l2tp", Product: vendor, Version: protocol, ExtraInfo: strings.Join(extra, " ")}
}

// sanitizeString keeps printable ASCII, capped at 256 bytes.
func sanitizeString(s string) string {
	if len(s) > 256 {
		s = s[:256]
	}
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 32 && s[i] < 127 {
			result = append(result, s[i])
		}
	}
	return string(result)
}
