// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package lwm2m

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/coap"
)

// Plugin detects OMA LwM2M (ports 5683/5783), a CoAP profile, by issuing the
// CoAP GET /.well-known/core probe and requiring the LwM2M-specific /rd
// registration resource in the CoRE Link Format payload.
type Plugin struct{}

func (Plugin) Name() string    { return "lwm2m" }
func (Plugin) Ports() []uint16 { return []uint16{5683, 5783} }
func (Plugin) Priority() int   { return 1999 }
func (Plugin) Payload(uint16) []byte {
	return []byte{
		0x40, 0x01, 0x13, 0x37,
		0xBB, '.', 'w', 'e', 'l', 'l', '-', 'k', 'n', 'o', 'w', 'n',
		0x04, 'c', 'o', 'r', 'e',
	}
}

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	msgID := make([]byte, 2)
	if _, err := rand.Read(msgID); err != nil {
		return nil, &udp.RandomizeError{Message: "lwm2m message id"}
	}
	probe := []byte{
		0x40, 0x01, msgID[0], msgID[1],
		0xBB, '.', 'w', 'e', 'l', 'l', '-', 'k', 'n', 'o', 'w', 'n',
		0x04, 'c', 'o', 'r', 'e',
	}

	response, err := udp.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 4 || (response[0]>>6) != 1 {
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

	payloadStr, ok := coap.PayloadString(response)
	if !ok || !strings.Contains(payloadStr, "</rd>") {
		return nil, nil
	}

	impl := "unknown"
	if strings.Contains(payloadStr, "Cf ") {
		impl = "leshan"
	}
	extra := "server=" + impl
	if strings.Contains(payloadStr, "</bs>") {
		extra += " bootstrap=true"
	}
	return &udp.Result{Name: "lwm2m", ExtraInfo: extra}, nil
}
