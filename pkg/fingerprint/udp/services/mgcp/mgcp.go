// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package mgcp

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects MGCP (Media Gateway Control Protocol, ports 2427/2727) with an
// AUEP (Audit Endpoint) command and validates the response line format.
type Plugin struct{}

// probe is an AUEP command with a wildcard endpoint and transaction ID 9.
var probe = []byte("AUEP 9 * MGCP 1.0\r\n\r\n")

// responsePattern matches a valid MGCP response first line: a 3-digit code and
// the transaction ID 9.
var responsePattern = regexp.MustCompile(`^\d{3}\s+9(\s+.*)?$`)

func (Plugin) Name() string          { return "mgcp" }
func (Plugin) Ports() []uint16       { return []uint16{2427, 2727} }
func (Plugin) Priority() int         { return 90 }
func (Plugin) Payload(uint16) []byte { return probe }

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	response, err := udp.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	lines := strings.Split(string(response), "\r\n")
	firstLine := strings.TrimSpace(lines[0])
	if !responsePattern.MatchString(firstLine) {
		return nil, nil
	}
	fields := strings.Fields(firstLine)
	if len(fields) < 2 {
		return nil, nil
	}
	if _, err := strconv.Atoi(fields[0]); err != nil {
		return nil, nil
	}

	result := &udp.Result{Name: "mgcp", ExtraInfo: "response_code=" + fields[0]}
	for _, line := range lines[1:] {
		if endpoint := strings.TrimSpace(strings.TrimPrefix(line, "Z: ")); strings.HasPrefix(line, "Z: ") && endpoint != "" {
			result.ExtraInfo += " endpoint=" + endpoint
			break
		}
	}
	return result, nil
}
