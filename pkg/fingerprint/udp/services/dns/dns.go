// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package dns

import (
	"bytes"
	"crypto/rand"
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects DNS servers by issuing a CHAOS-class "version.bind" TXT query
// and checking the transaction ID is echoed back.
type Plugin struct{}

// query is the DNS question body (everything after the 2-byte transaction ID):
// a standard query for version.bind / TXT / CH.
var query = []byte{
	0x01, 0x00, // Flags: standard query
	0x00, 0x01, // Questions: 1
	0x00, 0x00, // Answer RRs: 0
	0x00, 0x00, // Authority RRs: 0
	0x00, 0x00, // Additional RRs: 0
	0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e, 0x64, 0x00, // version.bind
	0x00, 0x10, // Type: TXT
	0x00, 0x03, // Class: CH
}

func (Plugin) Name() string    { return "dns" }
func (Plugin) Ports() []uint16 { return []uint16{53} }
func (Plugin) Priority() int   { return 50 }
func (Plugin) Payload(uint16) []byte {
	// A fixed transaction ID is fine for blind discovery.
	return append([]byte{0x13, 0x37}, query...)
}

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	for attempts := 0; attempts < 3; attempts++ {
		txID := make([]byte, 2)
		if _, err := rand.Read(txID); err != nil {
			return nil, &udp.RandomizeError{Message: "transaction ID"}
		}
		probe := append(append([]byte{}, txID...), query...)

		response, err := udp.SendRecv(conn, probe, timeout)
		if err != nil {
			return nil, err
		}
		if len(response) < 2 {
			return nil, nil
		}
		if !bytes.Equal(txID, response[0:2]) {
			return nil, nil
		}
	}
	return &udp.Result{Name: "dns"}, nil
}
