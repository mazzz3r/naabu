package coap

import "testing"

func TestPayloadString(t *testing.T) {
	// Header (4) + payload marker 0xFF + "</>;title=\"x\"".
	resp := []byte{0x60, 0x45, 0x13, 0x37, 0xFF}
	resp = append(resp, []byte("</>;rt=core")...)
	got, ok := PayloadString(resp)
	if !ok || got != "</>;rt=core" {
		t.Fatalf("PayloadString = %q,%v want payload", got, ok)
	}
}

func TestPayloadStringNoPayload(t *testing.T) {
	// Header only, no 0xFF marker: no payload.
	if _, ok := PayloadString([]byte{0x60, 0x45, 0x13, 0x37}); ok {
		t.Fatal("expected no payload")
	}
}

func TestExtractPayloadCaliforniumVersion(t *testing.T) {
	resp := []byte{0x60, 0x45, 0x13, 0x37, 0xFF}
	resp = append(resp, []byte("Cf 3.8.0 build")...)
	_, version := extractPayload(resp)
	if version != "3.8.0" {
		t.Fatalf("version = %q, want 3.8.0", version)
	}
}
