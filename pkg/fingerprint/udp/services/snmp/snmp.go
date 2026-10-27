// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package snmp

import (
	"bytes"
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects SNMP agents with a v1 GetRequest for sysDescr using the
// default "public" community string, reporting sysDescr as the version banner.
type Plugin struct{}

// requestID is the OID marker expected back in a valid response.
var requestID = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}

// getRequest is an SNMPv1 GET for sysDescr.0 with community "public".
var getRequest = []byte{
	0x30, 0x29,
	0x02, 0x01, 0x00, // Version: 1
	0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // Community: "public"
	0xa0, 0x1c, // PDU type: GET
	0x02, 0x04, 0xff, 0xff, 0xff, 0xff, // Request ID
	0x02, 0x01, 0x00, // Error status
	0x02, 0x01, 0x00, // Error index
	0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06,
	0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
}

const infoOffset = 33

func (Plugin) Name() string          { return "snmp" }
func (Plugin) Ports() []uint16       { return []uint16{161} }
func (Plugin) Priority() int         { return 81 }
func (Plugin) Payload(uint16) []byte { return getRequest }

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	response, err := udp.SendRecv(conn, getRequest, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}
	idx := strings.Index(string(response), "public")
	if idx == -1 || !bytes.Contains(response, requestID) {
		return nil, nil
	}
	result := &udp.Result{Name: "snmp"}
	if begin := idx + infoOffset; begin < len(response) {
		result.Version = string(response[begin:])
	}
	return result, nil
}
