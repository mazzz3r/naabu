// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package ntp

import (
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects NTP servers via an RFC 5905 client-mode packet, confirming
// the reply carries server mode (4) and the same length.
type Plugin struct{}

const modeServer = 4

// clientPacket is a mode-3 (client) NTP request; it doubles as the discovery
// payload since it carries no per-probe randomness.
var clientPacket = []byte{
	0xe3, 0x00, 0x0a, 0xf8, // LI/VN/Mode | Stratum | Poll | Precision
	0x00, 0x00, 0x00, 0x00, // Root Delay
	0x00, 0x00, 0x00, 0x00, // Root Dispersion
	0x00, 0x00, 0x00, 0x00, // Reference Identifier
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reference Timestamp
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Origin Timestamp
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Receive Timestamp
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Transmit Timestamp
}

func (Plugin) Name() string          { return "ntp" }
func (Plugin) Ports() []uint16       { return []uint16{123} }
func (Plugin) Priority() int         { return 800 }
func (Plugin) Payload(uint16) []byte { return clientPacket }

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	response, err := udp.SendRecv(conn, clientPacket, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) != len(clientPacket) {
		return nil, nil
	}
	if response[0]&0x07 != modeServer {
		return nil, nil
	}
	return &udp.Result{Name: "ntp"}, nil
}
