// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package tftp

import (
	"bytes"
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects TFTP (port 69) with a Read Request for a non-existent file
// and recognising the ERROR reply. TFTP servers answer from an ephemeral port,
// so the probe is sent over an unconnected packet socket.
type Plugin struct{}

// rrq is a TFTP Read Request for "naabu-probe.txt" in octet mode.
var rrq = []byte{
	0x00, 0x01, // Opcode: RRQ
	0x6e, 0x61, 0x61, 0x62, 0x75, 0x2d, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x2e, 0x74, 0x78, 0x74, // naabu-probe.txt
	0x00,                         // filename terminator
	0x6f, 0x63, 0x74, 0x65, 0x74, // "octet"
	0x00, // mode terminator
}

func (Plugin) Name() string          { return "tftp" }
func (Plugin) Ports() []uint16       { return []uint16{69} }
func (Plugin) Priority() int         { return 800 }
func (Plugin) Payload(uint16) []byte { return rrq }

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	targetAddr := conn.RemoteAddr()
	conn.Close() //nolint:errcheck

	pconn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}
	defer pconn.Close() //nolint:errcheck

	response, _, err := udp.SendRecvFrom(pconn, rrq, targetAddr, timeout)
	if err != nil {
		return nil, err
	}
	// A TFTP ERROR packet (opcode 5) confirms a live server.
	if len(response) < 4 || response[0] != 0x00 || response[1] != 0x05 {
		return nil, nil
	}

	result := &udp.Result{Name: "tftp"}
	if len(response) > 4 {
		msg := response[4:]
		if i := bytes.IndexByte(msg, 0x00); i >= 0 {
			msg = msg[:i]
		}
		result.ExtraInfo = "error=" + string(msg)
	}
	return result, nil
}
