// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package quic

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects any QUIC service (HTTP/3, SMB-over-QUIC, ...) by sending a
// long-header packet with an invalid version to force a Version Negotiation
// response (RFC 9000, RFC 8999), without doing any TLS crypto.
type Plugin struct{}

const (
	dcidLen     = 8
	minDatagram = 1200
)

var knownVersions = map[uint32]string{
	0x00000001: "QUICv1",
	0x6B3343CF: "QUICv2",
	0xFF000000: "draft-00",
}

func (Plugin) Name() string    { return "quic" }
func (Plugin) Ports() []uint16 { return []uint16{443} }
func (Plugin) Priority() int   { return 2100 }
func (Plugin) Payload(uint16) []byte {
	// A fixed DCID is fine for discovery; the Run path still verifies the echo.
	return buildVersionNegotiationProbe(bytes.Repeat([]byte{0xAB}, dcidLen))
}

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	dcid := make([]byte, dcidLen)
	if _, err := rand.Read(dcid); err != nil {
		return nil, &udp.RandomizeError{Message: "destination connection id"}
	}
	response, err := udp.SendRecv(conn, buildVersionNegotiationProbe(dcid), timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}
	versions, ok := parseVersionNegotiation(response, dcid)
	if !ok {
		return nil, nil
	}
	return &udp.Result{Name: "quic", ExtraInfo: "versions=" + join(versions)}, nil
}

func join(versions []string) string {
	out := ""
	for i, v := range versions {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}

// buildVersionNegotiationProbe builds a 1200-byte QUIC long-header packet with
// an invalid version (0xBABABABA) to trigger Version Negotiation.
func buildVersionNegotiationProbe(dcid []byte) []byte {
	probe := make([]byte, minDatagram)
	probe[0] = 0x80 // long header form
	probe[1] = 0xBA
	probe[2] = 0xBA
	probe[3] = 0xBA
	probe[4] = 0xBA
	probe[5] = byte(len(dcid))
	copy(probe[6:6+len(dcid)], dcid)
	probe[6+len(dcid)] = 0x00 // SCID length = 0
	return probe
}

// parseVersionNegotiation validates a QUIC Version Negotiation response and
// returns the advertised versions.
func parseVersionNegotiation(data, sentDCID []byte) ([]string, bool) {
	if len(data) < 11 || data[0]&0x80 == 0 {
		return nil, false
	}
	if binary.BigEndian.Uint32(data[1:5]) != 0x00000000 {
		return nil, false
	}
	offset := 5
	if offset >= len(data) {
		return nil, false
	}
	respDCIDLen := int(data[offset])
	offset++
	offset += respDCIDLen
	if offset >= len(data) {
		return nil, false
	}
	respSCIDLen := int(data[offset])
	offset++
	if offset+respSCIDLen > len(data) || respSCIDLen != len(sentDCID) {
		return nil, false
	}
	if !bytes.Equal(data[offset:offset+respSCIDLen], sentDCID) {
		return nil, false
	}
	offset += respSCIDLen

	remaining := len(data) - offset
	if remaining < 4 {
		return nil, false
	}
	var versions []string
	versionEnd := offset + (remaining/4)*4
	for offset+4 <= versionEnd {
		v := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		if name, ok := knownVersions[v]; ok {
			versions = append(versions, name)
		} else {
			versions = append(versions, fmt.Sprintf("0x%08X", v))
		}
	}
	if len(versions) == 0 {
		return nil, false
	}
	return versions, true
}
