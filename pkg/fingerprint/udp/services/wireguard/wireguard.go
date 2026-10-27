// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package wireguard

import (
	"bytes"
	"crypto/rand"
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects WireGuard (port 51820) by sending a handshake initiation and
// recognising a handshake response or cookie reply. On the default port it
// falls back to a lower-confidence silence heuristic.
type Plugin struct{}

const (
	msgTypeResponse = 0x02
	msgTypeCookie   = 0x03
	initiationSize  = 148
	responseSize    = 92
	cookieSize      = 64
	defaultPort     = 51820
)

func (Plugin) Name() string          { return "wireguard" }
func (Plugin) Ports() []uint16       { return []uint16{defaultPort} }
func (Plugin) Priority() int         { return 710 }
func (Plugin) Payload(uint16) []byte { p, _ := buildInitiation(make([]byte, 4)); return p }

// buildInitiation builds a 148-byte handshake initiation with the given sender
// index and random key material.
func buildInitiation(senderIndex []byte) ([]byte, error) {
	pkt := make([]byte, initiationSize)
	pkt[0] = 0x01 // message type: initiation
	copy(pkt[4:8], senderIndex)
	if _, err := rand.Read(pkt[8:132]); err != nil {
		return nil, &udp.RandomizeError{Message: "handshake fields"}
	}
	return pkt, nil
}

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	senderIndex := make([]byte, 4)
	if _, err := rand.Read(senderIndex); err != nil {
		return nil, &udp.RandomizeError{Message: "sender index"}
	}
	initPacket, err := buildInitiation(senderIndex)
	if err != nil {
		return nil, err
	}

	response, err := udp.SendRecv(conn, initPacket, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) > 0 {
		if method, ok := classify(response, senderIndex); ok {
			confidence := "high"
			if method == "response_unverified" {
				confidence = "medium"
			}
			return &udp.Result{Name: "wireguard", ExtraInfo: "method=" + method + " confidence=" + confidence}, nil
		}
		// A non-WireGuard reply rules it out.
		return nil, nil
	}

	// Differential probe: a byte-0 that is not a valid message type.
	garbage := make([]byte, initiationSize)
	if _, err := rand.Read(garbage[1:]); err != nil {
		return nil, &udp.RandomizeError{Message: "garbage packet"}
	}
	time.Sleep(100 * time.Millisecond)

	garbageResponse, err := udp.SendRecv(conn, garbage, timeout)
	if err != nil {
		return nil, err
	}
	if len(garbageResponse) == 0 {
		if target.Port == defaultPort {
			return &udp.Result{Name: "wireguard", ExtraInfo: "method=heuristic confidence=low"}, nil
		}
		return nil, nil
	}
	// Garbage answered but the WireGuard probe did not: differential signal.
	return &udp.Result{Name: "wireguard", ExtraInfo: "method=differential confidence=medium"}, nil
}

// classify reports the detection method for a response, if it is WireGuard.
func classify(response, senderIndex []byte) (string, bool) {
	if len(response) < 4 {
		return "", false
	}
	switch response[0] {
	case msgTypeCookie:
		if len(response) >= cookieSize {
			return "cookie", true
		}
	case msgTypeResponse:
		if len(response) >= responseSize {
			if bytes.Equal(response[8:12], senderIndex) {
				return "response", true
			}
			return "response_unverified", true
		}
	}
	return "", false
}
