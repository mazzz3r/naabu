package quic

import (
	"encoding/binary"
	"testing"
)

// buildVersionNegotiationResponse builds a well-formed VN packet echoing the
// client's DCID as the server SCID and advertising the given versions.
func buildVersionNegotiationResponse(clientDCID []byte, versions []uint32) []byte {
	pkt := []byte{0xC0}                       // long header, high bit set
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00) // version 0 => Version Negotiation
	pkt = append(pkt, 0x00)                   // server DCID length 0 (we sent SCID len 0)
	pkt = append(pkt, byte(len(clientDCID)))  // server SCID length echoes our DCID
	pkt = append(pkt, clientDCID...)          // ... and value
	for _, v := range versions {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		pkt = append(pkt, b[:]...)
	}
	return pkt
}

func TestParseVersionNegotiation(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	resp := buildVersionNegotiationResponse(dcid, []uint32{0x00000001, 0x6B3343CF, 0xDEADBEEF})

	versions, ok := parseVersionNegotiation(resp, dcid)
	if !ok {
		t.Fatal("expected a valid Version Negotiation response")
	}
	want := []string{"QUICv1", "QUICv2", "0xDEADBEEF"}
	if len(versions) != len(want) {
		t.Fatalf("versions = %v, want %v", versions, want)
	}
	for i := range want {
		if versions[i] != want[i] {
			t.Fatalf("versions[%d] = %q, want %q", i, versions[i], want[i])
		}
	}
}

func TestParseVersionNegotiationRejectsWrongSCID(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	resp := buildVersionNegotiationResponse([]byte{9, 9, 9, 9, 9, 9, 9, 9}, []uint32{0x00000001})
	if _, ok := parseVersionNegotiation(resp, dcid); ok {
		t.Fatal("expected rejection: echoed SCID does not match our DCID")
	}
}

func TestParseVersionNegotiationRejectsNonVN(t *testing.T) {
	// A non-zero version field is not a Version Negotiation packet.
	pkt := []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}
	if _, ok := parseVersionNegotiation(pkt, []byte{1, 2, 3, 4, 5, 6, 7, 8}); ok {
		t.Fatal("expected rejection of non-VN packet")
	}
}

func TestProbeIsMinimumDatagram(t *testing.T) {
	probe := buildVersionNegotiationProbe([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if len(probe) != minDatagram {
		t.Fatalf("probe length = %d, want %d", len(probe), minDatagram)
	}
	if probe[0] != 0x80 {
		t.Fatalf("probe[0] = 0x%02x, want 0x80 (long header)", probe[0])
	}
}
