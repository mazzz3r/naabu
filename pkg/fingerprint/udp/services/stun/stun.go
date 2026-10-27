// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package stun

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects STUN (RFC 8489, port 3478) by sending a Binding Request with
// a FINGERPRINT attribute and validating the Binding Response message type,
// magic cookie and transaction ID.
type Plugin struct{}

const (
	headerLen       = 20
	fingerprintLen  = 8
	bindingResponse = "0101"
	magicCookie     = "2112a442"
	fingerprintXor  = 0x5354554e
)

var attributes = map[uint32]string{
	0x0001: "MappedAddress",
	0x0006: "Username",
	0x0008: "MessageIntegrity",
	0x0009: "ErrorCode",
	0x000a: "UnknownAttributes",
	0x0014: "Realm",
	0x0015: "Nonce",
	0x0020: "XORMappedAddress",
	0x8022: "Software",
	0x8023: "AlternateServer",
	0x8028: "Fingerprint",
}

func (Plugin) Name() string    { return "stun" }
func (Plugin) Ports() []uint16 { return []uint16{3478} }
func (Plugin) Priority() int   { return 2000 }
func (Plugin) Payload(uint16) []byte {
	return buildBindingRequest(make([]byte, 12))
}

// buildBindingRequest builds a STUN Binding Request with the given 12-byte
// transaction ID and a trailing FINGERPRINT attribute.
func buildBindingRequest(transID []byte) []byte {
	pkt := []byte{
		0x00, 0x01, // Message Type: Binding Request
		0x00, 0x0c, // Message Length
		0x21, 0x12, 0xA4, 0x42, // Magic Cookie
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
		0x80, 0x22, 0x00, 0x00, // SOFTWARE (empty)
		0x80, 0x28, 0x00, 0x04, // FINGERPRINT
		0, 0, 0, 0, // CRC-32
	}
	copy(pkt[8:20], transID)
	fp := crc32.ChecksumIEEE(pkt[:len(pkt)-fingerprintLen]) ^ fingerprintXor
	for i := 1; i <= 4; i++ {
		pkt[len(pkt)-i] = byte(fp & 0xFF)
		fp >>= 8
	}
	return pkt
}

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	transID := make([]byte, 12)
	if _, err := rand.Read(transID); err != nil {
		return nil, &udp.RandomizeError{Message: "transaction ID"}
	}
	probe := buildBindingRequest(transID)

	response, err := udp.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < headerLen {
		return nil, nil
	}
	if hex.EncodeToString(response[:2]) != bindingResponse ||
		hex.EncodeToString(response[4:8]) != magicCookie ||
		hex.EncodeToString(response[8:20]) != hex.EncodeToString(transID) {
		return nil, nil
	}

	info := parseResponse(response)
	return &udp.Result{Name: "stun", ExtraInfo: fmt.Sprintf("%s", info)}, nil
}

// parseResponse extracts the STUN attributes from a response, keeping the first
// occurrence of each.
func parseResponse(response []byte) map[string]string {
	attrInfo := make(map[string]string)
	idx := headerLen
	for idx+4 <= len(response) {
		attrType := (int(response[idx]) << 8) + int(response[idx+1])
		attrLen := (int(response[idx+2]) << 8) + int(response[idx+3])
		idx += 4
		if attrLen == 0 {
			continue
		}
		if idx+attrLen > len(response) {
			break
		}
		attrValue := response[idx : idx+attrLen]
		idx += attrLen

		name, ok := attributes[uint32(attrType)]
		var value string
		switch {
		case ok && name == "Software":
			value = string(attrValue)
		case ok:
			value = hex.EncodeToString(attrValue)
		default:
			name = fmt.Sprintf("%04x", attrType)
			value = hex.EncodeToString(attrValue)
		}
		if _, exists := attrInfo[name]; !exists {
			attrInfo[name] = value
		}
	}
	return attrInfo
}
