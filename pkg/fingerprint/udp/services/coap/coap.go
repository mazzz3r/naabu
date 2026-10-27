// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package coap

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects CoAP (RFC 7252, port 5683) with a confirmable GET for
// /.well-known/core and validates the version, type and response code.
type Plugin struct{}

func (Plugin) Name() string    { return "coap" }
func (Plugin) Ports() []uint16 { return []uint16{5683} }
func (Plugin) Priority() int   { return 2000 }
func (Plugin) Payload(uint16) []byte {
	return buildProbe([]byte{0x13, 0x37})
}

// buildProbe builds a CoAP GET /.well-known/core request with the given 2-byte
// message ID.
func buildProbe(msgID []byte) []byte {
	return []byte{
		0x40, 0x01, msgID[0], msgID[1], // Ver=1, Type=CON, TKL=0, Code=GET
		0xBB, '.', 'w', 'e', 'l', 'l', '-', 'k', 'n', 'o', 'w', 'n', // Uri-Path ".well-known"
		0x04, 'c', 'o', 'r', 'e', // Uri-Path "core"
	}
}

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	msgID := make([]byte, 2)
	if _, err := rand.Read(msgID); err != nil {
		return nil, &udp.RandomizeError{Message: "coap message id"}
	}

	response, err := udp.SendRecv(conn, buildProbe(msgID), timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 4 {
		return nil, nil
	}
	if (response[0] >> 6) != 1 {
		return nil, nil
	}
	typ := (response[0] >> 4) & 0x03
	if typ != 1 && typ != 2 {
		return nil, nil
	}
	if codeClass := response[1] >> 5; codeClass != 2 && codeClass != 4 && codeClass != 5 {
		return nil, nil
	}
	if typ == 2 && binary.BigEndian.Uint16(response[2:4]) != binary.BigEndian.Uint16(msgID) {
		return nil, nil
	}

	resources, version := extractPayload(response)
	return &udp.Result{Name: "coap", Version: version, ExtraInfo: trimResources(resources)}, nil
}

func trimResources(resources string) string {
	if resources == "" {
		return ""
	}
	return "resources=" + resources
}

// extractPayload returns the CoAP payload and any Eclipse Californium ("Cf ")
// version string.
func extractPayload(response []byte) (resources, version string) {
	payloadStr, ok := PayloadString(response)
	if !ok {
		return "", ""
	}
	if cfIdx := strings.Index(payloadStr, "Cf "); cfIdx != -1 {
		rest := payloadStr[cfIdx+3:]
		if end := strings.IndexAny(rest, " \t\r\n"); end == -1 {
			version = rest
		} else {
			version = rest[:end]
		}
	}
	return payloadStr, version
}

// PayloadString walks the CoAP options of a response and returns the payload
// that follows the 0xFF marker. The second return is false on any parse error
// or when there is no payload. It is exported so the LwM2M plugin, which layers
// on CoAP, can reuse the same option walker.
func PayloadString(response []byte) (string, bool) {
	if len(response) < 4 {
		return "", false
	}
	tkl := int(response[0] & 0x0F)
	idx := 4 + tkl

	for idx < len(response) {
		b := response[idx]
		idx++
		if b == 0xFF {
			break
		}
		switch int(b >> 4) {
		case 13:
			if idx >= len(response) {
				return "", false
			}
			idx++
		case 14:
			if idx+1 >= len(response) {
				return "", false
			}
			idx += 2
		case 15:
			return "", false
		}
		optLen := int(b & 0x0F)
		switch optLen {
		case 13:
			if idx >= len(response) {
				return "", false
			}
			optLen = int(response[idx]) + 13
			idx++
		case 14:
			if idx+1 >= len(response) {
				return "", false
			}
			optLen = int(binary.BigEndian.Uint16(response[idx:idx+2])) + 269
			idx += 2
		case 15:
			return "", false
		}
		if idx+optLen > len(response) {
			return "", false
		}
		idx += optLen
	}
	if idx >= len(response) {
		return "", false
	}
	return string(response[idx:]), true
}
