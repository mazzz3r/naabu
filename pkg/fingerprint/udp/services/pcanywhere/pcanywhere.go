// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package pcanywhere

import (
	"bytes"
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects Symantec pcAnywhere's UDP status listener (port 5632) with
// Nmap's "NQ" probe, recognising the "NR...AHM_3___" status reply.
type Plugin struct{}

// statusProbe is Nmap's UDP pc-anywhere probe.
var statusProbe = []byte("NQ")

func (Plugin) Name() string          { return "pcanywhere" }
func (Plugin) Ports() []uint16       { return []uint16{5632} }
func (Plugin) Priority() int         { return 100 }
func (Plugin) Payload(uint16) []byte { return statusProbe }

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	response, err := udp.SendRecv(conn, statusProbe, timeout)
	if err != nil {
		return nil, err
	}
	if !isStatusReply(response) {
		return nil, nil
	}
	result := &udp.Result{
		Name: "pcanywhere",
		CPEs: []string{"cpe:2.3:a:symantec:pcanywhere:*:*:*:*:*:*:*:*"},
	}
	if name := replyName(response); name != "" {
		result.ExtraInfo = "host=" + name
	}
	return result, nil
}

// isStatusReply matches Nmap's ^NR([^_]*)_*AHM_3___\0 pattern.
func isStatusReply(data []byte) bool {
	if !bytes.HasPrefix(data, []byte("NR")) || !bytes.HasSuffix(data, []byte{0}) {
		return false
	}
	const marker = "AHM_3___"
	idx := bytes.Index(data, []byte(marker))
	if idx < 2 || idx+len(marker) != len(data)-1 {
		return false
	}
	mid := data[2:idx]
	i := 0
	for i < len(mid) && mid[i] != '_' {
		i++
	}
	for ; i < len(mid); i++ {
		if mid[i] != '_' {
			return false
		}
	}
	return true
}

// replyName extracts the host name from a pcAnywhere status reply.
func replyName(data []byte) string {
	idx := bytes.Index(data, []byte("AHM_3___"))
	if idx < 2 {
		return ""
	}
	mid := data[2:idx]
	n := 0
	for n < len(mid) && mid[n] != '_' {
		n++
	}
	return string(mid[:n])
}
