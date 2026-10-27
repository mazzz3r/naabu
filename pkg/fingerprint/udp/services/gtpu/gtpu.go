// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package gtpu

import (
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects the GTP-U user plane (3GPP TS 29.281, port 2152) via a GTPv1
// Echo Request, confirming version 1, PT=1 and an Echo Response message type.
type Plugin struct{}

// echoRequest is a GTPv1-U Echo Request with the sequence flag set.
var echoRequest = []byte{
	0x32,       // Version=1, PT=1, S=1
	0x01,       // Message Type: Echo Request
	0x00, 0x04, // Length
	0x00, 0x00, 0x00, 0x00, // TEID
	0x00, 0x00, // Sequence Number
	0x00, // N-PDU Number
	0x00, // Next Extension Header Type
}

func (Plugin) Name() string          { return "gtpu" }
func (Plugin) Ports() []uint16       { return []uint16{2152} }
func (Plugin) Priority() int         { return 81 }
func (Plugin) Payload(uint16) []byte { return echoRequest }

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	response, err := udp.SendRecv(conn, echoRequest, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 2 {
		return nil, nil
	}
	version := (response[0] >> 5) & 0x07
	pt := (response[0] >> 4) & 0x01
	if version != 1 || pt != 1 || response[1] != 0x02 {
		return nil, nil
	}
	return &udp.Result{Name: "gtpu"}, nil
}
