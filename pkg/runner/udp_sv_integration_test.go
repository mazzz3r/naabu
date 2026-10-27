package runner

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/stretchr/testify/require"
)

// startDNSResponder brings up a UDP server on 127.0.0.1:53 that answers the
// native DNS plugin's version.bind query by echoing the transaction ID with the
// QR bit set. Port 53 is required because the built-in discovery payload is
// keyed to a plugin's declared ports; the test is skipped when :53 cannot be
// bound (not privileged, or already in use). It returns the port and a stop func.
func startDNSResponder(t *testing.T) (int, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:53")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:53 for the DNS responder: %v", err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { _ = pc.Close() }) }
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 3 {
				continue
			}
			reply := make([]byte, n)
			copy(reply, buf[:n])
			reply[2] = 0x81 // QR=1 (response)
			_, _ = pc.WriteTo(reply, addr)
		}
	}()
	_, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	p, _ := net.LookupPort("udp", portStr)
	return p, stop
}

// TestUDPServiceVersionWithoutNmap exercises the whole pipeline end to end: a
// connect-mode UDP scan discovers the open port using the built-in payload and
// -sV identifies it as DNS through the native UDP engine — with no
// nmap-service-probes database involved.
func TestUDPServiceVersionWithoutNmap(t *testing.T) {
	// This drives a real connect-mode UDP scan, which opens raw UDP listen
	// sockets and binds :53. Sandboxed/seccomp CI kills that, so the test is
	// opt-in: set NAABU_UDP_SV_IT=1 on a privileged host to run it.
	if os.Getenv("NAABU_UDP_SV_IT") == "" {
		t.Skip("set NAABU_UDP_SV_IT=1 to run the UDP -sV integration test (needs privileges)")
	}

	dnsPort, stop := startDNSResponder(t)
	defer stop()

	var (
		mu      sync.Mutex
		results []*result.HostResult
	)

	opts := &Options{
		Host:           []string{"127.0.0.1"},
		Ports:          "u:" + itoa(dnsPort),
		ScanType:       ConnectScan,
		ServiceVersion: true,
		// Force the native UDP path only: no nmap probe file on this box.
		ServiceProbesFile:     "/nonexistent/nmap-service-probes",
		ServiceVersionWorkers: 5,
		ServiceVersionTimeout: 2 * time.Second,
		Retries:               1,
		Timeout:               2 * time.Second,
		DisableStdout:         true,
		DisableStdin:          true,
		OnResult: func(hr *result.HostResult) {
			mu.Lock()
			results = append(results, hr)
			mu.Unlock()
		},
	}

	runner, err := NewRunner(opts)
	require.NoError(t, err)
	defer runner.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	require.NoError(t, runner.RunEnumeration(ctx))

	mu.Lock()
	defer mu.Unlock()

	var dnsSvc *port.Service
	for _, hr := range results {
		for _, p := range hr.Ports {
			if p.Port == dnsPort && p.Protocol == protocol.UDP && p.Service != nil {
				dnsSvc = p.Service
			}
		}
	}
	require.NotNil(t, dnsSvc, "expected a UDP service on the DNS port; results=%+v", results)
	require.Equal(t, "dns", dnsSvc.Name)
}

// itoa avoids importing strconv just for the port string.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
