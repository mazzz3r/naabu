// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package omronfins

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects OMRON FINS PLCs (port 9600) with a Read Controller Data
// request (0x0501) and reports the controller model and version.
type Plugin struct{}

// readControllerData is a FINS Read Controller Data request.
var readControllerData = []byte{
	0x80, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x63, 0x00, 0xEF,
	0x05, 0x01, 0x00,
}

func (Plugin) Name() string          { return "omron-fins" }
func (Plugin) Ports() []uint16       { return []uint16{9600} }
func (Plugin) Priority() int         { return 400 }
func (Plugin) Payload(uint16) []byte { return readControllerData }

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	response, err := udp.SendRecv(conn, readControllerData, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	model, version, ok := parseControllerData(response)
	if !ok {
		return nil, nil
	}
	return &udp.Result{
		Name:    "omron-fins",
		Product: model,
		Version: version,
		CPEs:    generateCPE(model, version),
	}, nil
}

// parseControllerData validates a FINS Read Controller Data response and
// extracts the model and version strings.
func parseControllerData(data []byte) (model, version string, ok bool) {
	if len(data) < 14 {
		return "", "", false
	}
	if icf := data[0]; icf != 0xC0 && icf != 0xC1 {
		return "", "", false
	}
	if binary.BigEndian.Uint16(data[12:14]) != 0x0000 {
		return "", "", false
	}

	switch {
	case len(data) >= 14+20:
		model = extractNullTerminatedString(data[14:34])
	case len(data) > 14:
		model = extractNullTerminatedString(data[14:])
	}
	model = sanitizeString(model)

	switch {
	case len(data) >= 34+20:
		version = extractNullTerminatedString(data[34:54])
	case len(data) > 34:
		version = extractNullTerminatedString(data[34:])
	}
	version = sanitizeString(version)

	return model, version, true
}

func extractNullTerminatedString(b []byte) string {
	for i, c := range b {
		if c == 0x00 {
			return string(b[:i])
		}
	}
	return string(b)
}

// sanitizeString keeps only printable ASCII.
func sanitizeString(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 0x20 && c <= 0x7E {
			result = append(result, c)
		}
	}
	return strings.TrimSpace(string(result))
}

// generateCPE builds a CPE 2.3 string for OMRON hardware.
func generateCPE(model, version string) []string {
	if model == "" {
		return nil
	}
	versionSlug := "*"
	if version != "" {
		versionSlug = normalizeCPE(version)
	}
	return []string{fmt.Sprintf("cpe:2.3:h:omron:%s:%s:*:*:*:*:*:*:*", normalizeCPE(model), versionSlug)}
}

// normalizeCPE lowercases alphanumerics and maps space/-/./ to underscore.
func normalizeCPE(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '.':
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "*"
	}
	return b.String()
}
