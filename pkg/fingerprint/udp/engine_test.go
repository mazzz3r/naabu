package udp

import (
	"context"
	"net"
	"testing"
	"time"
)

// fakePlugin is a configurable in-memory plugin for engine tests.
type fakePlugin struct {
	name     string
	ports    []uint16
	priority int
	payload  []byte
	// match, when non-nil, is the response substring that makes Run report a hit.
	run func(conn net.Conn, timeout time.Duration, t Target) (*Result, error)
}

func (f fakePlugin) Name() string          { return f.name }
func (f fakePlugin) Ports() []uint16       { return f.ports }
func (f fakePlugin) Priority() int         { return f.priority }
func (f fakePlugin) Payload(uint16) []byte { return f.payload }
func (f fakePlugin) Run(c net.Conn, to time.Duration, t Target) (*Result, error) {
	if f.run != nil {
		return f.run(c, to, t)
	}
	return nil, nil
}

func TestUDPProbePrefersHighestPriority(t *testing.T) {
	e := NewEngine([]Plugin{
		fakePlugin{name: "low", ports: []uint16{53}, priority: 100, payload: []byte("low")},
		fakePlugin{name: "high", ports: []uint16{53}, priority: 10, payload: []byte("high")},
		fakePlugin{name: "noPayload", ports: []uint16{53}, priority: 1, payload: nil},
	})
	// Priority 1 has no payload, so the next-highest with a payload (priority 10) wins.
	if got := e.UDPProbe(53); string(got) != "high" {
		t.Fatalf("UDPProbe(53) = %q, want %q", got, "high")
	}
	if got := e.UDPProbe(9999); got != nil {
		t.Fatalf("UDPProbe(9999) = %q, want nil", got)
	}
	if got := e.UDPProbe(-1); got != nil {
		t.Fatalf("UDPProbe(-1) = %q, want nil (out of range)", got)
	}
}

// echoServer starts a UDP server that replies to each datagram with reply.
func echoServer(t *testing.T, reply []byte) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, addr, err := pc.ReadFrom(buf)
			select {
			case <-done:
				return
			default:
			}
			if err != nil {
				continue
			}
			if n > 0 {
				_, _ = pc.WriteTo(reply, addr)
			}
		}
	}()
	host, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	return host + ":" + portStr, func() { close(done); pc.Close() }
}

func TestDetectReturnsFirstMatch(t *testing.T) {
	addr, stop := echoServer(t, []byte("PONG"))
	defer stop()
	host, portStr, _ := net.SplitHostPort(addr)
	port := atoiPort(t, portStr)

	hit := fakePlugin{
		name: "pong", ports: []uint16{uint16(port)}, priority: 10,
		run: func(c net.Conn, to time.Duration, _ Target) (*Result, error) {
			resp, err := SendRecv(c, []byte("ping"), to)
			if err != nil {
				return nil, err
			}
			if string(resp) == "PONG" {
				return &Result{Name: "pong"}, nil
			}
			return nil, nil
		},
	}
	miss := fakePlugin{name: "miss", ports: []uint16{uint16(port)}, priority: 5}

	e := NewEngine([]Plugin{hit, miss}, WithTimeout(time.Second))
	r := e.Detect(context.Background(), Target{IP: host, Port: port})
	if r == nil || r.Name != "pong" {
		t.Fatalf("Detect = %+v, want pong", r)
	}
}

func TestDetectFastModeSkipsFallback(t *testing.T) {
	addr, stop := echoServer(t, []byte("X"))
	defer stop()
	host, portStr, _ := net.SplitHostPort(addr)
	port := atoiPort(t, portStr)

	// A plugin that matches but is NOT port-hinted for this port. In fast mode
	// it must never run.
	fallback := fakePlugin{
		name: "fallback", ports: []uint16{1}, priority: 1,
		run: func(net.Conn, time.Duration, Target) (*Result, error) {
			return &Result{Name: "fallback"}, nil
		},
	}
	e := NewEngine([]Plugin{fallback}, WithTimeout(time.Second), WithFastMode(true))
	if r := e.Detect(context.Background(), Target{IP: host, Port: port}); r != nil {
		t.Fatalf("fast mode ran a non-hinted plugin: %+v", r)
	}

	// With fast mode off, the fallback runs against any port and matches.
	e2 := NewEngine([]Plugin{fallback}, WithTimeout(time.Second))
	if r := e2.Detect(context.Background(), Target{IP: host, Port: port}); r == nil {
		t.Fatalf("slow mode should have run the fallback plugin")
	}
}

func TestFingerprintStream(t *testing.T) {
	addr, stop := echoServer(t, []byte("PONG"))
	defer stop()
	host, portStr, _ := net.SplitHostPort(addr)
	port := atoiPort(t, portStr)

	hit := fakePlugin{
		name: "pong", ports: []uint16{uint16(port)}, priority: 10,
		run: func(c net.Conn, to time.Duration, _ Target) (*Result, error) {
			resp, _ := SendRecv(c, []byte("ping"), to)
			if string(resp) == "PONG" {
				return &Result{Name: "pong"}, nil
			}
			return nil, nil
		},
	}
	e := NewEngine([]Plugin{hit}, WithTimeout(time.Second), WithWorkers(2))

	targets := make(chan Target, 1)
	targets <- Target{IP: host, Port: port}
	close(targets)

	var got []StreamResult
	for sr := range e.FingerprintStream(context.Background(), targets) {
		got = append(got, sr)
	}
	if len(got) != 1 || got[0].Service.Name != "pong" {
		t.Fatalf("FingerprintStream = %+v, want one pong", got)
	}
}

func atoiPort(t *testing.T, s string) int {
	t.Helper()
	p, err := net.LookupPort("udp", s)
	if err != nil {
		t.Fatalf("bad port %q: %v", s, err)
	}
	return p
}
