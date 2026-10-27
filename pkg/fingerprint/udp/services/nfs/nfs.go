// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package nfs

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects NFS over UDP (port 2049) by issuing Sun RPC NULL calls for
// NFS v3 and v2 (v4 is TCP-only per RFC 7530) and reporting the highest version
// that answers.
type Plugin struct{}

const nfsProgramNumber = 100003

func (Plugin) Name() string          { return "nfs" }
func (Plugin) Ports() []uint16       { return []uint16{2049} }
func (Plugin) Priority() int         { return 350 }
func (Plugin) Payload(uint16) []byte { return buildNullCall(0x12345678, 3) }

// buildNullCall builds a 40-byte UDP RPC NULL call for the given NFS version.
func buildNullCall(xid, version uint32) []byte {
	buf := make([]byte, 40)
	binary.BigEndian.PutUint32(buf[0:4], xid)
	binary.BigEndian.PutUint32(buf[4:8], 0) // CALL
	binary.BigEndian.PutUint32(buf[8:12], 2)
	binary.BigEndian.PutUint32(buf[12:16], nfsProgramNumber)
	binary.BigEndian.PutUint32(buf[16:20], version)
	binary.BigEndian.PutUint32(buf[20:24], 0) // NULL procedure
	// AUTH_NULL credentials + verifier (remaining 16 bytes stay zero).
	return buf
}

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	xid := generateXID()
	var detected []int
	for _, version := range []uint32{3, 2} {
		response, err := udp.SendRecv(conn, buildNullCall(xid, version), timeout)
		if err != nil {
			return nil, err
		}
		if len(response) == 0 {
			continue
		}
		if parseReply(response, xid) {
			detected = append(detected, int(version))
		}
	}
	if len(detected) == 0 {
		return nil, nil
	}
	return &udp.Result{
		Name:      "nfs",
		Version:   fmt.Sprintf("%d", detected[0]),
		ExtraInfo: fmt.Sprintf("versions=%v", detected),
	}, nil
}

func generateXID() uint32 {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return 0x12345678
	}
	return binary.BigEndian.Uint32(b)
}

// parseReply validates a UDP RPC reply (no record marker) and checks that the
// NULL procedure was accepted.
func parseReply(response []byte, expectedXID uint32) bool {
	if len(response) < 24 {
		return false
	}
	if binary.BigEndian.Uint32(response[0:4]) != expectedXID {
		return false
	}
	if binary.BigEndian.Uint32(response[4:8]) != 1 { // REPLY
		return false
	}
	if binary.BigEndian.Uint32(response[8:12]) != 0 { // MSG_ACCEPTED
		return false
	}
	// Skip verifier (8 bytes), then accept stat.
	return binary.BigEndian.Uint32(response[20:24]) == 0 // SUCCESS
}
