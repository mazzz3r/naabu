// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package iax2

import (
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects IAX2 (Inter-Asterisk eXchange v2, RFC 5456, port 4569) by
// sending a POKE and checking the reply is an IAX Control frame with a
// PONG/ACK/CALLTOKEN subclass.
type Plugin struct{}

const frameTypeIAXControl = 0x06

var validSubclasses = map[byte]bool{
	0x03: true, // PONG
	0x04: true, // ACK
	0x28: true, // CALLTOKEN
}

// pokePacket is a 12-byte IAX2 POKE (full frame, IAX Control, subclass POKE).
var pokePacket = []byte{
	0x80, 0x00, // Source call number (full frame)
	0x00, 0x00, // Dest call number
	0x00, 0x00, 0x00, 0x00, // Timestamp
	0x00, // oseqno
	0x00, // iseqno
	0x06, // Frame type: IAX Control
	0x1e, // Subclass: POKE
}

func (Plugin) Name() string          { return "iax2" }
func (Plugin) Ports() []uint16       { return []uint16{4569} }
func (Plugin) Priority() int         { return 2000 }
func (Plugin) Payload(uint16) []byte { return pokePacket }

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	response, err := udp.SendRecv(conn, pokePacket, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 12 || response[10] != frameTypeIAXControl || !validSubclasses[response[11]] {
		return nil, nil
	}
	return &udp.Result{Name: "iax2"}, nil
}
