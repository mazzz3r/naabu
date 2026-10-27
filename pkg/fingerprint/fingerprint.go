package fingerprint

import (
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
)

// Target represents a host:port to fingerprint.
type Target struct {
	Host string
	IP   string
	Port int
	// Protocol is the transport the port was found on. The zero value is
	// protocol.TCP, so existing TCP callers need no change; the runner sets
	// it to protocol.UDP for UDP ports so service detection routes them to
	// the native UDP engine instead of the TCP probe engine.
	Protocol protocol.Protocol
	// TLSDetected indicates whether TLS was detected during port scanning.
	TLSDetected bool
	// TLSChecked indicates that TLS detection was already performed during the
	// port scanning phase. When true, the engine trusts TLSDetected and skips
	// its own TLS probe, saving one TCP connection per target.
	TLSChecked bool
}

// Result is the output of a successful probe match.
type Result struct {
	Name       string
	Product    string
	Version    string
	ExtraInfo  string
	OSType     string
	DeviceType string
	Banner     string
	TLS        bool
	CPEs       []string
}

// ToService converts a fingerprint Result into a port.Service.
func (r *Result) ToService() *port.Service {
	return &port.Service{
		Name:       r.Name,
		Product:    r.Product,
		Version:    r.Version,
		ExtraInfo:  r.ExtraInfo,
		OSType:     r.OSType,
		DeviceType: r.DeviceType,
		Banner:     r.Banner,
		Method:     "probes",
		CPEs:       r.CPEs,
	}
}
