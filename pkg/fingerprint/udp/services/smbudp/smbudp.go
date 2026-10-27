// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package smbudp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects SMB over QUIC (MS-SMB2, port 443/udp) by completing a QUIC
// handshake with ALPN "smb". A successful "smb" negotiation distinguishes it
// from HTTP/3 and other QUIC applications.
//
// The handshake is driven by quic-go on its own UDP transport, so the net.Conn
// the engine hands in is not used — the plugin dials the target address again.
type Plugin struct{}

const alpnSMB = "smb"

func (Plugin) Name() string          { return "smb" }
func (Plugin) Ports() []uint16       { return []uint16{443} }
func (Plugin) Priority() int         { return 2099 } // before generic QUIC (2100)
func (Plugin) Payload(uint16) []byte { return nil }  // needs a handshake, not a static datagram

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	addr := target.Addr()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tlsConf := &tls.Config{ //nolint:gosec // InsecureSkipVerify is required for scanning unknown hosts
		NextProtos:         []string{alpnSMB},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13, // QUIC mandates TLS 1.3
	}

	quicConn, err := quic.DialAddr(ctx, addr, tlsConf, nil)
	if err != nil {
		// Either no QUIC, or QUIC without ALPN "smb" (e.g. HTTP/3 "h3").
		return nil, nil //nolint:nilerr
	}
	defer quicConn.CloseWithError(0, "") //nolint:errcheck

	state := quicConn.ConnectionState().TLS
	if state.NegotiatedProtocol != alpnSMB {
		return nil, nil
	}

	result := &udp.Result{
		Name:      "smb",
		ExtraInfo: fmt.Sprintf("quic_version=0x%08X", quicConn.ConnectionState().Version),
	}
	if len(state.PeerCertificates) > 0 {
		result.ExtraInfo += " cert_subject=" + state.PeerCertificates[0].Subject.String()
	}
	return result, nil
}
