// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package sip

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects SIP (RFC 3261, port 5060/udp) with an OPTIONS request and
// extracts the Server header, product, version and a CPE when recognised.
type Plugin struct{}

const defaultSIPPort = 5060

var versionPatterns = []struct {
	product string
	pattern *regexp.Regexp
}{
	{"Asterisk", regexp.MustCompile(`Asterisk\s+PBX\s+(\d+\.\d+\.\d+)`)},
	{"Audiocodes", regexp.MustCompile(`Audiocodes[^\d]*Mediant\s*(\d+)`)},
	{"Kamailio", regexp.MustCompile(`Kamailio/(\d+\.\d+\.\d+)`)},
	{"Kamailio", regexp.MustCompile(`(?i)kamailio\s*\((\d+\.\d+\.\d+)`)},
	{"OpenSIPS", regexp.MustCompile(`OpenSIPS/(\d+\.\d+\.\d+)`)},
	{"FreeSWITCH", regexp.MustCompile(`(?i)FreeSWITCH[^\d]*(\d+\.\d+(?:\.\d+)?)`)},
	{"FreePBX", regexp.MustCompile(`FPBX[^\d]*(\d+\.\d+\.\d+)`)},
	{"Cisco", regexp.MustCompile(`Cisco[^\d]*(\d+\.\d+)`)},
	{"3CX", regexp.MustCompile(`3CXPhoneSystem\s+(\d+\.\d+)`)},
	{"TANDBERG", regexp.MustCompile(`TANDBERG/\d+\s+\(([\w.]+)\)`)},
}

var serverPatterns = []struct {
	product string
	pattern *regexp.Regexp
}{
	{"Asterisk", regexp.MustCompile(`(?i)Asterisk`)},
	{"Audiocodes", regexp.MustCompile(`(?i)Audiocodes`)},
	{"Kamailio", regexp.MustCompile(`(?i)kamailio`)},
	{"OpenSIPS", regexp.MustCompile(`(?i)OpenSIPS`)},
	{"FreeSWITCH", regexp.MustCompile(`(?i)FreeSWITCH`)},
	{"FreePBX", regexp.MustCompile(`(?i)FreePBX|FPBX`)},
	{"Cisco", regexp.MustCompile(`(?i)Cisco`)},
	{"3CX", regexp.MustCompile(`(?i)3CX`)},
	{"TANDBERG", regexp.MustCompile(`(?i)TANDBERG`)},
}

var cpeVendors = map[string]string{
	"Asterisk":   "cpe:2.3:a:digium:asterisk:%s:*:*:*:*:*:*:*",
	"Audiocodes": "cpe:2.3:h:audiocodes:mediant_%s:*:*:*:*:*:*:*:*",
	"Kamailio":   "cpe:2.3:a:kamailio:kamailio:%s:*:*:*:*:*:*:*",
	"OpenSIPS":   "cpe:2.3:a:opensips:opensips:%s:*:*:*:*:*:*:*",
	"FreeSWITCH": "cpe:2.3:a:freeswitch:freeswitch:%s:*:*:*:*:*:*:*",
	"FreePBX":    "cpe:2.3:a:freepbx:freepbx:%s:*:*:*:*:*:*:*",
	"Cisco":      "cpe:2.3:a:cisco:unified_communications_manager:%s:*:*:*:*:*:*:*",
	"3CX":        "cpe:2.3:a:3cx:phone_system:%s:*:*:*:*:*:*:*",
	"TANDBERG":   "cpe:2.3:h:cisco:telepresence_codec:%s:*:*:*:*:*:*:*",
}

func (Plugin) Name() string          { return "sip" }
func (Plugin) Ports() []uint16       { return []uint16{defaultSIPPort} }
func (Plugin) Priority() int         { return 50 }
func (Plugin) Payload(uint16) []byte { return buildOPTIONSRequest("UDP") }

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	response, err := udp.SendRecv(conn, buildOPTIONSRequest("UDP"), timeout)
	if err != nil {
		return nil, err
	}
	if !validateSIPResponse(response) {
		return nil, nil
	}

	server := extractHeader(response, "Server")
	product, version := extractSIPVersion(server)

	result := &udp.Result{Name: "sip", Product: product, Version: version, Banner: server}
	if cpe := buildSIPCPE(product, version); cpe != "" {
		result.CPEs = []string{cpe}
	}
	if methods := parseAllowHeader(response); len(methods) > 0 {
		result.ExtraInfo = "allow=" + strings.Join(methods, ",")
	}
	return result, nil
}

// buildOPTIONSRequest builds an RFC 3261 OPTIONS request for the given transport.
func buildOPTIONSRequest(transport string) []byte {
	return []byte(fmt.Sprintf(
		"OPTIONS sip:100@127.0.0.1 SIP/2.0\r\n"+
			"Via: SIP/2.0/%s 127.0.0.1:5060;branch=z9hG4bK776asdhds\r\n"+
			"Max-Forwards: 70\r\n"+
			"To: <sip:100@127.0.0.1>\r\n"+
			"From: <sip:scanner@127.0.0.1>;tag=1928301774\r\n"+
			"Call-ID: a84b4c76e66710@127.0.0.1\r\n"+
			"CSeq: 63104 OPTIONS\r\n"+
			"Contact: <sip:scanner@127.0.0.1>\r\n"+
			"Accept: application/sdp\r\n"+
			"Content-Length: 0\r\n\r\n",
		strings.ToUpper(transport)))
}

// validateSIPResponse reports whether the response starts with a valid SIP
// status line.
func validateSIPResponse(response []byte) bool {
	if len(response) < 12 || !bytes.HasPrefix(response, []byte("SIP/2.0 ")) {
		return false
	}
	statusCode := response[8:11]
	for i := 0; i < 3; i++ {
		if statusCode[i] < '0' || statusCode[i] > '9' {
			return false
		}
	}
	code := (int(statusCode[0])-'0')*100 + (int(statusCode[1])-'0')*10 + (int(statusCode[2]) - '0')
	return code >= 100 && code < 700
}

// extractSIPVersion returns a product name and version from a Server header.
func extractSIPVersion(serverHeader string) (product, version string) {
	if serverHeader == "" {
		return "", ""
	}
	for _, vp := range versionPatterns {
		if matches := vp.pattern.FindStringSubmatch(serverHeader); len(matches) >= 2 {
			return vp.product, matches[1]
		}
	}
	for _, sp := range serverPatterns {
		if sp.pattern.MatchString(serverHeader) {
			return sp.product, ""
		}
	}
	return "", ""
}

// buildSIPCPE renders the CPE for a detected SIP product, if known.
func buildSIPCPE(product, version string) string {
	template, ok := cpeVendors[product]
	if !ok {
		return ""
	}
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf(template, version)
}

// extractHeader returns a SIP header value (case-insensitive).
func extractHeader(response []byte, headerName string) string {
	headerNameLower := strings.ToLower(headerName)
	for _, line := range bytes.Split(response, []byte("\r\n")) {
		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx == -1 {
			continue
		}
		if strings.TrimSpace(strings.ToLower(string(line[:colonIdx]))) == headerNameLower {
			return strings.TrimSpace(string(line[colonIdx+1:]))
		}
	}
	return ""
}

// parseAllowHeader splits the Allow header into methods.
func parseAllowHeader(response []byte) []string {
	allow := extractHeader(response, "Allow")
	if allow == "" {
		return nil
	}
	var result []string
	for _, method := range strings.Split(allow, ",") {
		if method = strings.TrimSpace(method); method != "" {
			result = append(result, method)
		}
	}
	return result
}
