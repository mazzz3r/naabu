// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package openvpn

import (
	"bytes"
	"crypto/rand"
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects OpenVPN by sending a CLIENT_RESET control message and
// checking for a SERVER_RESET that echoes the session ID. It does not detect
// servers configured with tls-auth (they drop the packet on HMAC failure).
type Plugin struct{}

const (
	opcodeShift       = 3
	hardResetClientV2 = 7
	hardResetServerV2 = 8
	sessionIDLen      = 8
)

func (Plugin) Name() string          { return "openvpn" }
func (Plugin) Ports() []uint16       { return []uint16{1194} }
func (Plugin) Priority() int         { return 708 }
func (Plugin) Payload(uint16) []byte { return clientReset(make([]byte, sessionIDLen)) }

func clientReset(sessionID []byte) []byte {
	pkt := []byte{
		hardResetClientV2 << opcodeShift, // opcode/key_id
		0, 0, 0, 0, 0, 0, 0, 0,           // session ID
		0,          // packet-id array length
		0, 0, 0, 0, // message packet-id
	}
	copy(pkt[1:1+sessionIDLen], sessionID)
	return pkt
}

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	sessionID := make([]byte, sessionIDLen)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, &udp.RandomizeError{Message: "session ID"}
	}
	response, err := udp.SendRecv(conn, clientReset(sessionID), timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 || response[0]>>opcodeShift != hardResetServerV2 {
		return nil, nil
	}
	for i := 0; i+sessionIDLen <= len(response); i++ {
		if bytes.Equal(response[i:i+sessionIDLen], sessionID) {
			return &udp.Result{Name: "openvpn"}, nil
		}
	}
	return nil, nil
}
