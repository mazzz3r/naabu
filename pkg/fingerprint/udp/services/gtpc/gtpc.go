// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package gtpc

import (
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects the GTP-C control plane (port 2123) in both GTPv2-C (3GPP TS
// 29.274) and GTPv1-C (3GPP TS 29.060) flavours via an Echo Request, reporting
// the negotiated version.
type Plugin struct{}

var gtpv2EchoRequest = []byte{
	0x40,       // Version=2, P=0, T=0
	0x01,       // Message Type: Echo Request
	0x00, 0x04, // Message Length
	0x00, 0x00, 0x01, // Sequence Number
	0x00, // Spare
}

var gtpv1EchoRequest = []byte{
	0x32,       // Version=1, PT=1, S=1
	0x01,       // Message Type: Echo Request
	0x00, 0x04, // Length
	0x00, 0x00, 0x00, 0x00, // TEID
	0x00, 0x01, // Sequence Number
	0x00, // N-PDU Number
	0x00, // Next Extension Header Type
}

func (Plugin) Name() string          { return "gtpc" }
func (Plugin) Ports() []uint16       { return []uint16{2123} }
func (Plugin) Priority() int         { return 79 }
func (Plugin) Payload(uint16) []byte { return gtpv2EchoRequest }

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	// GTPv2-C first (more common on modern networks).
	if response, err := udp.SendRecv(conn, gtpv2EchoRequest, timeout); err == nil && isGTPv2(response) {
		return &udp.Result{Name: "gtpc", Version: "GTPv2"}, nil
	}
	if response, err := udp.SendRecv(conn, gtpv1EchoRequest, timeout); err == nil && isGTPv1(response) {
		return &udp.Result{Name: "gtpc", Version: "GTPv1"}, nil
	}
	return nil, nil
}

func isGTPv2(response []byte) bool {
	if len(response) < 2 {
		return false
	}
	return (response[0]>>5)&0x07 == 2 && response[1] == 0x02
}

func isGTPv1(response []byte) bool {
	if len(response) < 2 {
		return false
	}
	version := (response[0] >> 5) & 0x07
	pt := (response[0] >> 4) & 0x01
	return version == 1 && pt == 1 && response[1] == 0x02
}
