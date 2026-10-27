// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package megaco

import (
	"bytes"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects MEGACO/H.248 media gateway controllers (ports 2944/2945) with
// a text-mode ServiceChange (cold boot) request and parses the version and MID
// out of the reply.
type Plugin struct{}

// probeMessage is a MEGACO/1 ServiceChange request mimicking a gateway cold boot.
var probeMessage = []byte("MEGACO/1 [0.0.0.0]\nTransaction = 1 {\n  Context = - {\n    ServiceChange = ROOT {\n      Services {\n        Method = Restart,\n        Reason = \"901 Cold Boot\"\n      }\n    }\n  }\n}\n")

var (
	prettyPattern  = regexp.MustCompile(`(?i)^MEGACO/(\d+)\s*\[([^\]]*)\]`)
	compactPattern = regexp.MustCompile(`^!/(\d+)\s*\[([^\]]*)\]`)
)

func (Plugin) Name() string          { return "megaco" }
func (Plugin) Ports() []uint16       { return []uint16{2944, 2945} }
func (Plugin) Priority() int         { return 90 }
func (Plugin) Payload(uint16) []byte { return probeMessage }

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	response, err := udp.SendRecv(conn, probeMessage, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	version, mid, ok := parseMegacoResponse(response)
	if !ok {
		return nil, nil
	}
	result := &udp.Result{Name: "megaco", Version: version}
	if mid != "" {
		result.ExtraInfo = "mid=" + mid
	}
	return result, nil
}

// parseMegacoResponse validates a MEGACO message (pretty or compact format) and
// returns the version and MID.
func parseMegacoResponse(data []byte) (version, mid string, ok bool) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return "", "", false
	}
	if matches := prettyPattern.FindSubmatch(trimmed); matches != nil {
		return string(matches[1]), strings.TrimSpace(string(matches[2])), true
	}
	if matches := compactPattern.FindSubmatch(trimmed); matches != nil {
		return string(matches[1]), strings.TrimSpace(string(matches[2])), true
	}
	return "", "", false
}
