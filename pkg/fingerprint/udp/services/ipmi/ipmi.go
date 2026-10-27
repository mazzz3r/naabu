// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package ipmi

import (
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects IPMI BMC interfaces (port 623) with a Get Channel
// Authentication Capabilities request, reporting the supported auth types,
// IPMI v2 support and whether anonymous login is permitted.
type Plugin struct{}

// getAuthCapabilities is the RMCP Get Channel Authentication Capabilities
// request; it carries no randomness, so it doubles as the discovery payload.
var getAuthCapabilities = []byte{
	0x06, 0x00, 0xFF, 0x07, // RMCP header, class IPMI
	0x00,                   // auth type NONE
	0x00, 0x00, 0x00, 0x00, // session ID
	0x00, 0x00, 0x00, 0x00, // session sequence
	0x09,                                                 // message length
	0x20, 0x18, 0xC8, 0x81, 0x00, 0x38, 0x8E, 0x04, 0xB5, // IPMB command
}

// expectedPrefix is the fixed RMCP+session header a valid reply opens with.
var expectedPrefix = []byte{
	0x06, 0x00, 0xFF, 0x07,
	0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

const (
	authCapabilitiesMinLen = 25
	offsetCompletionCode   = 20
	offsetAuthTypeSupport  = 22
	offsetAuthStatus       = 23
	offsetExtCapabilities  = 24
	authStatusAnonymous    = 0x01
	extCapIPMIv2           = 0x02
)

func (Plugin) Name() string          { return "ipmi" }
func (Plugin) Ports() []uint16       { return []uint16{623} }
func (Plugin) Priority() int         { return 80 }
func (Plugin) Payload(uint16) []byte { return getAuthCapabilities }

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	response, err := udp.SendRecv(conn, getAuthCapabilities, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < len(expectedPrefix) {
		return nil, nil
	}
	for i, b := range expectedPrefix {
		if response[i] != b {
			return nil, nil
		}
	}

	result := &udp.Result{Name: "ipmi"}
	result.ExtraInfo = describeAuthCapabilities(response)
	return result, nil
}

// describeAuthCapabilities renders the auth type bitmap, IPMI v2 support and
// anonymous-login flag from a Get Channel Authentication Capabilities response.
func describeAuthCapabilities(response []byte) string {
	if len(response) < authCapabilitiesMinLen || response[offsetCompletionCode] != 0x00 {
		return ""
	}
	authTypes := response[offsetAuthTypeSupport]
	var parts []string
	if types := authTypeList(authTypes); len(types) > 0 {
		parts = append(parts, "auth_types="+strings.Join(types, ","))
	}
	if response[offsetExtCapabilities]&extCapIPMIv2 != 0 {
		parts = append(parts, "ipmi_v2=true")
	}
	if response[offsetAuthStatus]&authStatusAnonymous != 0 {
		parts = append(parts, "anonymous_login=true")
	}
	return strings.Join(parts, " ")
}

// authTypeList decodes the IPMI 2.0 auth type support bitmap (Table 22-15).
func authTypeList(bitmap byte) []string {
	var types []string
	for _, bit := range []struct {
		mask byte
		name string
	}{
		{0x01, "none"},
		{0x02, "md2"},
		{0x04, "md5"},
		{0x10, "straight_key"},
		{0x20, "oem"},
	} {
		if bitmap&bit.mask != 0 {
			types = append(types, bit.name)
		}
	}
	return types
}
