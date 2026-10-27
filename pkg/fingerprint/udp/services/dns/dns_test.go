package dns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// TestRunDetectsDNS runs the real DNS plugin against a local responder that
// echoes the transaction ID with the QR (response) bit set, proving end-to-end
// detection works with no nmap and no network.
func TestRunDetectsDNS(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 2048)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 3 {
				continue
			}
			reply := make([]byte, n)
			copy(reply, buf[:n])
			reply[2] = 0x81 // QR=1
			_, _ = pc.WriteTo(reply, addr)
		}
	}()

	host, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	port, _ := net.LookupPort("udp", portStr)

	e := udp.NewEngine([]udp.Plugin{Plugin{}}, udp.WithTimeout(2*time.Second))
	r := e.Detect(context.Background(), udp.Target{IP: host, Port: port})
	if r == nil || r.Name != "dns" {
		t.Fatalf("Detect = %+v, want dns", r)
	}
}
