package udp

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

// DialFunc opens a UDP connection. The engine defaults to net.Dialer but the
// runner can inject a proxy-aware dialer.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Engine runs the UDP plugin set against targets. It is built once from an
// explicit plugin list (no global registry) so independent engines can
// coexist in the same process.
type Engine struct {
	all      []Plugin            // every plugin, priority-ordered (slow lane)
	byPort   map[uint16][]Plugin // port-hinted plugins, priority-ordered
	payloads map[uint16][]byte   // discovery payload per hinted port
	timeout  time.Duration
	workers  int
	fast     bool
	dialer   DialFunc
}

// Option configures an Engine.
type Option func(*Engine)

// WithTimeout sets the per-probe timeout.
func WithTimeout(d time.Duration) Option { return func(e *Engine) { e.timeout = d } }

// WithWorkers sets the number of concurrent detection workers.
func WithWorkers(n int) Option { return func(e *Engine) { e.workers = n } }

// WithFastMode restricts detection to port-hinted plugins only.
func WithFastMode(v bool) Option { return func(e *Engine) { e.fast = v } }

// WithDialer injects a custom (e.g. proxy-aware) dialer.
func WithDialer(d DialFunc) Option { return func(e *Engine) { e.dialer = d } }

// StreamResult is one identified service emitted by FingerprintStream.
type StreamResult struct {
	IP      string
	Port    int
	Service *Result
}

// NewEngine builds an Engine from the given plugins. The list is indexed by
// port and by priority once, up front, so detection does no sorting.
func NewEngine(plugins []Plugin, opts ...Option) *Engine {
	e := &Engine{
		byPort:   make(map[uint16][]Plugin),
		payloads: make(map[uint16][]byte),
		timeout:  5 * time.Second,
		workers:  25,
	}
	for _, o := range opts {
		o(e)
	}

	e.all = append(e.all, plugins...)
	sortByPriority(e.all)

	for _, p := range e.all {
		for _, port := range p.Ports() {
			e.byPort[port] = append(e.byPort[port], p)
		}
	}
	for port, list := range e.byPort {
		sortByPriority(list)
		// The highest-priority plugin that offers a static payload owns the
		// discovery probe for this port.
		for _, p := range list {
			if payload := p.Payload(port); len(payload) > 0 {
				e.payloads[port] = payload
				break
			}
		}
	}
	return e
}

func sortByPriority(list []Plugin) {
	sort.SliceStable(list, func(i, j int) bool {
		return list[i].Priority() < list[j].Priority()
	})
}

// UDPProbe implements scan.UDPProbeProvider: it returns the discovery payload
// for a destination port, or nil when no plugin owns one.
func (e *Engine) UDPProbe(port int) []byte {
	if e == nil || port < 0 || port > 0xffff {
		return nil
	}
	return e.payloads[uint16(port)]
}

// Detect identifies the service on a single UDP target. It runs the
// port-hinted plugins first and, unless in fast mode, falls back to every
// remaining plugin ordered by rarity (priority). The first positive match
// wins.
func (e *Engine) Detect(ctx context.Context, t Target) *Result {
	port := uint16(t.Port)

	// Fast lane: plugins that claim this port, by priority.
	if r := e.runPlugins(ctx, t, e.byPort[port], false); r != nil {
		return r
	}
	if e.fast {
		return nil
	}
	// Slow lane: every other plugin (those not already tried above).
	return e.runPlugins(ctx, t, e.all, true)
}

// runPlugins tries each plugin in order and returns the first match. When
// skipHinted is set, plugins that claim the target port are skipped because
// the fast lane already ran them.
func (e *Engine) runPlugins(ctx context.Context, t Target, list []Plugin, skipHinted bool) *Result {
	port := uint16(t.Port)
	for _, p := range list {
		if ctx.Err() != nil {
			return nil
		}
		if skipHinted && claimsPort(p, port) {
			continue
		}
		conn, err := e.dial(ctx, t, p)
		if err != nil {
			continue
		}
		result, runErr := p.Run(conn, e.timeout, t)
		conn.Close() //nolint:errcheck
		if runErr == nil && result != nil {
			if result.Name == "" {
				result.Name = p.Name()
			}
			return result
		}
	}
	return nil
}

// claimsPort reports whether a plugin lists port among its default ports.
func claimsPort(p Plugin, port uint16) bool {
	for _, candidate := range p.Ports() {
		if candidate == port {
			return true
		}
	}
	return false
}

// dial opens a UDP connection to the target, binding the plugin's required
// source port when it declares one (DHCP).
func (e *Engine) dial(ctx context.Context, t Target, p Plugin) (net.Conn, error) {
	if binder, ok := p.(srcPortBinder); ok && e.dialer == nil {
		laddr := &net.UDPAddr{Port: int(binder.SrcPort())}
		raddr, err := net.ResolveUDPAddr("udp", t.Addr())
		if err != nil {
			return nil, err
		}
		return net.DialUDP("udp", laddr, raddr)
	}
	if e.dialer != nil {
		return e.dialer(ctx, "udp", t.Addr())
	}
	d := net.Dialer{Timeout: e.timeout}
	return d.DialContext(ctx, "udp", t.Addr())
}

// FingerprintStream detects services for targets arriving on a channel and
// emits results as they are identified, overlapping detection with discovery.
// It mirrors fingerprint.Engine.FingerprintStream so the runner can drive the
// TCP and UDP engines with identical plumbing.
func (e *Engine) FingerprintStream(ctx context.Context, targets <-chan Target) <-chan StreamResult {
	results := make(chan StreamResult, e.workers*2)

	var wg sync.WaitGroup
	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range targets {
				if ctx.Err() != nil {
					return
				}
				if r := e.Detect(ctx, t); r != nil {
					select {
					case results <- StreamResult{IP: t.IP, Port: t.Port, Service: r}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}
