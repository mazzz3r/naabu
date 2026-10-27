// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package gtpprime

import (
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects GTP' (GTP Prime, 3GPP TS 32.295, port 3386) charging
// interfaces via a GTPv1 Echo Request with PT=0, which distinguishes it from
// GTP-C/GTP-U (PT=1).
type Plugin struct{}

var echoRequest = []byte{
	0x20,       // Version=1, PT=0
	0x01,       // Message Type: Echo Request
	0x00, 0x00, // Length
	0x00, 0x00, 0x00, 0x00, // TEID
}

func (Plugin) Name() string          { return "gtpprime" }
func (Plugin) Ports() []uint16       { return []uint16{3386} }
func (Plugin) Priority() int         { return 80 }
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
	if version != 1 || pt != 0 || response[1] != 0x02 {
		return nil, nil
	}
	return &udp.Result{Name: "gtpprime"}, nil
}
