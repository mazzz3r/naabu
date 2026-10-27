// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package rdpeudp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects the RDP UDP transport (MS-RDPEUDP, port 3389/udp) by sending
// an RDPUDP SYN and validating a SYN+ACK response.
type Plugin struct{}

const (
	flagSYN   = 0x0001
	flagACK   = 0x0004
	flagSYNEX = 0x1000
)

func (Plugin) Name() string    { return "rdpeudp" }
func (Plugin) Ports() []uint16 { return []uint16{3389} }
func (Plugin) Priority() int   { return 90 }
func (Plugin) Payload(uint16) []byte {
	p, _ := buildSYNProbe(make([]byte, 4))
	return p
}

// buildSYNProbe builds a 16-byte RDPUDP SYN datagram. Field byte order follows
// other MS protocols (little-endian).
func buildSYNProbe(initialSeq []byte) ([]byte, error) {
	probe := make([]byte, 16)
	binary.LittleEndian.PutUint32(probe[0:4], 0xFFFFFFFF) // snSourceAck
	binary.LittleEndian.PutUint16(probe[4:6], 16)         // uReceiveWindowSize
	binary.LittleEndian.PutUint16(probe[6:8], flagSYN)    // uFlags
	copy(probe[8:12], initialSeq)                         // snInitialSequenceNumber
	binary.LittleEndian.PutUint16(probe[12:14], 1232)     // uUpStreamMtu
	binary.LittleEndian.PutUint16(probe[14:16], 1232)     // uDownStreamMtu
	return probe, nil
}

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	initialSeq := make([]byte, 4)
	if _, err := rand.Read(initialSeq); err != nil {
		return nil, &udp.RandomizeError{Message: "initial sequence number"}
	}
	probe, _ := buildSYNProbe(initialSeq)

	response, err := udp.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 16 {
		return nil, nil
	}
	flags := binary.LittleEndian.Uint16(response[6:8])
	if flags&flagSYN == 0 || flags&flagACK == 0 {
		return nil, nil
	}

	result := &udp.Result{
		Name: "rdpeudp",
		ExtraInfo: fmt.Sprintf("upstream_mtu=%d downstream_mtu=%d",
			binary.LittleEndian.Uint16(response[12:14]),
			binary.LittleEndian.Uint16(response[14:16])),
	}
	if flags&flagSYNEX != 0 && len(response) >= 20 {
		result.Version = fmt.Sprintf("%d", binary.LittleEndian.Uint16(response[18:20]))
	}
	return result, nil
}
