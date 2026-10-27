// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package ethercat

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects EtherCAT-over-UDP (port 34980) with a read-only Broadcast Read
// (BRD) command and validates the frame type, echoed index and a non-zero
// working counter.
type Plugin struct{}

func (Plugin) Name() string    { return "ethercat" }
func (Plugin) Ports() []uint16 { return []uint16{34980} }
func (Plugin) Priority() int   { return 400 }
func (Plugin) Payload(uint16) []byte {
	return buildBroadcastReadProbe(0x37)
}

// buildBroadcastReadProbe builds an EtherCAT BRD probe reading address 0x0000
// with the given Tx/Rx index byte.
func buildBroadcastReadProbe(index byte) []byte {
	probe := make([]byte, 14)
	frameHeader := uint16(12) | (uint16(1) << 14) // length 12, type 1 (EtherCAT)
	binary.LittleEndian.PutUint16(probe[0:2], frameHeader)
	probe[2] = 0x07  // Cmd: BRD
	probe[3] = index // Index
	// ADP, ADO, Length, IRQ, Working Counter all zero.
	return probe
}

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	index := make([]byte, 1)
	if _, err := rand.Read(index); err != nil {
		return nil, &udp.RandomizeError{Message: "ethercat index"}
	}
	probe := buildBroadcastReadProbe(index[0])

	response, err := udp.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if !isValidEtherCATResponse(response, index[0]) {
		return nil, nil
	}

	workingCounter, datagramCount := parseEtherCATResponse(response)
	return &udp.Result{
		Name:      "ethercat",
		ExtraInfo: fmt.Sprintf("working_counter=%d datagrams=%d", workingCounter, datagramCount),
	}, nil
}

// isValidEtherCATResponse checks the frame type, index echo and working counter.
func isValidEtherCATResponse(data []byte, probeIndex byte) bool {
	if len(data) < 14 {
		return false
	}
	frameHeader := binary.LittleEndian.Uint16(data[0:2])
	if (frameHeader>>14)&0x03 != 1 {
		return false
	}
	if data[3] != probeIndex {
		return false
	}
	return binary.LittleEndian.Uint16(data[12:14]) != 0
}

// parseEtherCATResponse walks the datagram chain and returns the last working
// counter and the datagram count.
func parseEtherCATResponse(data []byte) (workingCounter uint16, datagramCount int) {
	if len(data) < 14 {
		return 0, 0
	}
	offset := 2
	for offset+12 <= len(data) {
		datagramCount++
		lengthFlags := binary.LittleEndian.Uint16(data[offset+6 : offset+8])
		workingCounter = binary.LittleEndian.Uint16(data[offset+10 : offset+12])
		dataLen := lengthFlags & 0x7FF
		offset += 12 + int(dataLen)
		if (lengthFlags>>15)&0x01 == 0 {
			break
		}
	}
	return workingCounter, datagramCount
}
