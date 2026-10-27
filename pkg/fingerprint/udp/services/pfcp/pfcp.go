// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package pfcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects PFCP (3GPP TS 29.244, N4 interface, port 8805) with a
// Heartbeat Request and extracts the Recovery Time Stamp and Node ID from the
// response IEs.
type Plugin struct{}

// heartbeatRequest is a PFCP Heartbeat Request carrying a Recovery Time Stamp IE.
var heartbeatRequest = []byte{
	0x20,       // Version=1, S=0
	0x01,       // Message Type: Heartbeat Request
	0x00, 0x0c, // Message Length
	0x00, 0x00, 0x01, // Sequence Number
	0x00,       // Spare
	0x00, 0x60, // IE Type: Recovery Time Stamp
	0x00, 0x04, // IE Length
	0x00, 0x00, 0x00, 0x01, // Recovery Time Stamp
}

const (
	ieTypeNodeID            = 60
	ieTypeRecoveryTimeStamp = 96
)

func (Plugin) Name() string          { return "pfcp" }
func (Plugin) Ports() []uint16       { return []uint16{8805} }
func (Plugin) Priority() int         { return 80 }
func (Plugin) Payload(uint16) []byte { return heartbeatRequest }

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	response, err := udp.SendRecv(conn, heartbeatRequest, timeout)
	if err != nil {
		return nil, err
	}
	// Version 1, message type Heartbeat Response (0x02).
	if len(response) < 8 || (response[0]>>5)&0x07 != 1 || response[1] != 0x02 {
		return nil, nil
	}

	recoveryTS, nodeID := enrich(response)
	result := &udp.Result{Name: "pfcp"}
	var extra string
	if nodeID != "" {
		extra = "node_id=" + nodeID
	}
	if recoveryTS != 0 {
		if extra != "" {
			extra += " "
		}
		extra += fmt.Sprintf("recovery_ts=%d", recoveryTS)
	}
	result.ExtraInfo = extra
	return result, nil
}

// enrich extracts the Recovery Time Stamp and Node ID IEs from a PFCP response.
func enrich(response []byte) (recoveryTS uint32, nodeID string) {
	offset := 8
	for offset+4 <= len(response) {
		ieType := binary.BigEndian.Uint16(response[offset : offset+2])
		ieLen := int(binary.BigEndian.Uint16(response[offset+2 : offset+4]))
		offset += 4
		if offset+ieLen > len(response) {
			break
		}
		switch ieType {
		case ieTypeRecoveryTimeStamp:
			if ieLen >= 4 {
				recoveryTS = binary.BigEndian.Uint32(response[offset : offset+4])
			}
		case ieTypeNodeID:
			if ieLen >= 1 {
				switch response[offset] {
				case 0: // IPv4
					if ieLen >= 5 {
						nodeID = net.IP(response[offset+1 : offset+5]).String()
					}
				case 1: // IPv6
					if ieLen >= 17 {
						nodeID = net.IP(response[offset+1 : offset+17]).String()
					}
				case 2: // FQDN
					if ieLen >= 2 {
						nodeID = string(response[offset+1 : offset+ieLen])
					}
				}
			}
		}
		offset += ieLen
	}
	return recoveryTS, nodeID
}
