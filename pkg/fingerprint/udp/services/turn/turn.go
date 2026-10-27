// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package turn

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects TURN (RFC 8656, ports 3478/5349) by sending an unauthenticated
// Allocate request and expecting a 401/437 Allocate Error Response with REALM
// and NONCE, which distinguishes TURN from STUN-only servers. Priority runs it
// before the STUN plugin.
type Plugin struct{}

const (
	headerLen             = 20
	allocateErrorResponse = "0113"
	magicCookie           = "2112a442"
)

func (Plugin) Name() string    { return "turn" }
func (Plugin) Ports() []uint16 { return []uint16{3478, 5349} }
func (Plugin) Priority() int   { return 1999 }
func (Plugin) Payload(uint16) []byte {
	return buildAllocate(make([]byte, 12))
}

// buildAllocate builds a TURN Allocate request with the given 12-byte
// transaction ID and a REQUESTED-TRANSPORT=UDP attribute.
func buildAllocate(transID []byte) []byte {
	pkt := []byte{
		0x00, 0x03, // Message Type: Allocate
		0x00, 0x08, // Message Length
		0x21, 0x12, 0xA4, 0x42, // Magic Cookie
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
		0x00, 0x19, 0x00, 0x04, // REQUESTED-TRANSPORT
		0x11, 0x00, 0x00, 0x00, // Protocol: UDP
	}
	copy(pkt[8:20], transID)
	return pkt
}

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	transID := make([]byte, 12)
	if _, err := rand.Read(transID); err != nil {
		return nil, &udp.RandomizeError{Message: "transaction ID"}
	}
	probe := buildAllocate(transID)

	response, err := udp.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < headerLen {
		return nil, nil
	}
	if hex.EncodeToString(response[:2]) != allocateErrorResponse ||
		hex.EncodeToString(response[4:8]) != magicCookie ||
		hex.EncodeToString(response[8:20]) != hex.EncodeToString(transID) {
		return nil, nil
	}

	software, realm, nonce, ok := parseResponse(response)
	if !ok {
		return nil, nil
	}
	var extra []string
	if software != "" {
		extra = append(extra, "software="+software)
	}
	if realm != "" {
		extra = append(extra, "realm="+realm)
	}
	if nonce != "" {
		extra = append(extra, "nonce="+nonce)
	}
	return &udp.Result{Name: "turn", ExtraInfo: strings.Join(extra, " ")}, nil
}

// parseResponse extracts the TURN attributes and reports whether the response
// carries a TURN error code (401 or 437).
func parseResponse(response []byte) (software, realm, nonce string, ok bool) {
	idx := headerLen
	turnError := false
	for idx+4 <= len(response) {
		attrType := (uint32(response[idx]) << 8) + uint32(response[idx+1])
		attrLen := (int(response[idx+2]) << 8) + int(response[idx+3])
		idx += 4
		if attrLen == 0 {
			continue
		}
		if idx+attrLen > len(response) {
			return "", "", "", false
		}
		attrValue := response[idx : idx+attrLen]
		switch attrType {
		case 0x8022:
			software = string(attrValue)
		case 0x0014:
			realm = string(attrValue)
		case 0x0015:
			nonce = string(attrValue)
		case 0x0009:
			if attrLen >= 4 {
				errorCode := (uint16(attrValue[2]&0x07) * 100) + uint16(attrValue[3])
				if errorCode == 401 || errorCode == 437 {
					turnError = true
				}
			}
		}
		paddedLen := attrLen
		if attrLen%4 != 0 {
			paddedLen += 4 - (attrLen % 4)
		}
		idx += paddedLen
	}
	return software, realm, nonce, turnError
}
