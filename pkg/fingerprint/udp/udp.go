// Package udp provides native UDP service detection for naabu.
//
// Unlike TCP service version detection (-sV), which relies on the
// nmap-service-probes database, UDP detection is fully self-contained:
// every protocol is implemented as a small plugin that knows how to craft
// the one request a silent UDP service needs before it will answer, and how
// to recognise that answer. This keeps UDP scanning useful even when nmap is
// not installed.
//
// The plugin sources were adapted from the Nerva fingerprinting engine
// (github.com/praetorian-inc/nerva), which is licensed under the Apache
// License 2.0; see the NOTICE file in this directory.
package udp

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// Target identifies a single UDP endpoint to probe.
type Target struct {
	Host string
	IP   string
	Port int
}

// Addr returns the ip:port the probe should be sent to.
func (t Target) Addr() string {
	return net.JoinHostPort(t.IP, fmt.Sprintf("%d", t.Port))
}

// Result is what a plugin reports when it positively identifies a service.
// Its fields map one-to-one onto the subset of port.Service that UDP
// detection can populate, so the runner can copy them across without any
// protocol-specific knowledge.
type Result struct {
	Name      string
	Product   string
	Version   string
	ExtraInfo string
	Banner    string
	CPEs      []string
}

// Plugin detects a single UDP protocol.
//
// Implementations must be safe for concurrent use: the engine runs one
// plugin per goroutine against independent connections.
type Plugin interface {
	// Name is the service name reported on a match (e.g. "dns").
	Name() string
	// Ports lists the ports this plugin is the default owner of. During a
	// scan these are tried first (the "port-hinted" fast lane).
	Ports() []uint16
	// Priority orders plugins within a lane; lower runs first.
	Priority() int
	// Payload returns a representative probe datagram for blind port
	// discovery on the given port, or nil when the protocol cannot be
	// elicited with a single static datagram (e.g. it needs a handshake).
	Payload(port uint16) []byte
	// Run sends the plugin's probe over conn and returns a non-nil Result
	// when the peer is positively identified, or (nil, nil) when it is not.
	Run(conn net.Conn, timeout time.Duration, target Target) (*Result, error)
}

// srcPortBinder is an optional plugin capability: a protocol (DHCP) that
// only answers when the request originates from a fixed source port
// implements it, and the engine binds that port when dialing.
type srcPortBinder interface {
	SrcPort() uint16
}

// Send writes data to conn under a write deadline.
func Send(conn net.Conn, data []byte, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	n, err := conn.Write(data)
	if err != nil {
		return err
	}
	if n < len(data) {
		return fmt.Errorf("short write: %d of %d bytes", n, len(data))
	}
	return nil
}

// Recv reads a single datagram from conn under a read deadline. A timeout or
// an ICMP port-unreachable (ECONNREFUSED) is reported as an empty response
// with no error, so callers treat "silent" and "closed" the same way.
func Recv(conn net.Conn, timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 4096)
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	n, err := conn.Read(buf)
	if err != nil {
		var netErr net.Error
		if (errors.As(err, &netErr) && netErr.Timeout()) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, nil
		}
		return buf[:n], err
	}
	return buf[:n], nil
}

// SendRecv sends data and returns the first datagram the peer sends back.
func SendRecv(conn net.Conn, data []byte, timeout time.Duration) ([]byte, error) {
	if err := Send(conn, data, timeout); err != nil {
		return nil, err
	}
	return Recv(conn, timeout)
}

// SendRecvFrom sends data to addr over an unconnected packet socket and reads
// the reply from any source. It exists for protocols such as TFTP whose
// server answers from an ephemeral port rather than the one addressed.
func SendRecvFrom(conn net.PacketConn, data []byte, addr net.Addr, timeout time.Duration) ([]byte, net.Addr, error) {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, err
	}
	if _, err := conn.WriteTo(data, addr); err != nil {
		return nil, nil, err
	}
	buf := make([]byte, 4096)
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, err
	}
	n, src, err := conn.ReadFrom(buf)
	if err != nil {
		var netErr net.Error
		if (errors.As(err, &netErr) && netErr.Timeout()) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, nil, nil
		}
		return buf[:n], src, err
	}
	return buf[:n], src, nil
}

// RandomizeError is returned when crypto/rand fails while a plugin is
// building a probe that needs unpredictable bytes (transaction IDs, nonces).
type RandomizeError struct{ Message string }

func (e *RandomizeError) Error() string {
	return fmt.Sprintf("failed to generate random bytes [%s]", e.Message)
}

// InvalidAddrProvided is returned when a plugin needs a concrete address and
// did not get one.
type InvalidAddrProvided struct{ Service string }

func (e *InvalidAddrProvided) Error() string {
	return fmt.Sprintf("a valid address is required for %s service", e.Service)
}
