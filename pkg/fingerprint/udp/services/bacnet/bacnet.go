// Adapted from github.com/praetorian-inc/nerva (Apache-2.0); see
// pkg/fingerprint/udp/NOTICE.
package bacnet

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// Plugin detects BACnet/IP building-automation devices (port 47808) with a
// Who-Is broadcast, parses the I-Am reply and, when it learns the device
// instance, enriches with ReadProperty requests for Model-Name and
// Firmware-Revision.
type Plugin struct{}

const (
	propModelName        = 0x46
	propFirmwareRevision = 0x2C
	serviceReadProperty  = 0x0C
)

// whoIs is a BACnet Who-Is unicast request; it carries no randomness.
var whoIs = []byte{
	0x81, 0x0A, 0x00, 0x08, // BVLC
	0x01, 0x00, // NPDU
	0x10, 0x08, // APDU: Unconfirmed-Request, Who-Is
}

// deviceInfo holds the fields parsed out of an I-Am reply.
type deviceInfo struct {
	DeviceInstance uint32
	VendorID       uint16
	VendorName     string
	MaxAPDU        uint16
	Segmentation   string
	ModelName      string
	FirmwareRev    string
	CPEs           []string
}

func (Plugin) Name() string          { return "bacnet" }
func (Plugin) Ports() []uint16       { return []uint16{47808} }
func (Plugin) Priority() int         { return 400 }
func (Plugin) Payload(uint16) []byte { return whoIs }

func (Plugin) Run(conn net.Conn, timeout time.Duration, target udp.Target) (*udp.Result, error) {
	response, err := udp.SendRecv(conn, whoIs, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	info, ok := parseIAm(response)
	if !ok {
		return nil, nil
	}

	if info.DeviceInstance > 0 {
		model, firmware := enrichWithReadProperty(conn, timeout, info.DeviceInstance)
		if model != "" && info.ModelName == "" {
			info.ModelName = model
		}
		if firmware != "" && info.FirmwareRev == "" {
			info.FirmwareRev = firmware
		}
		info.CPEs = generateCPE(info.VendorID, info.ModelName, info.FirmwareRev)
	}

	result := &udp.Result{
		Name:    "bacnet",
		Product: info.ModelName,
		Version: info.FirmwareRev,
		CPEs:    info.CPEs,
	}
	var extra []string
	if info.VendorName != "" {
		extra = append(extra, "vendor="+info.VendorName)
	}
	extra = append(extra, fmt.Sprintf("device_instance=%d", info.DeviceInstance))
	if info.Segmentation != "" {
		extra = append(extra, "segmentation="+info.Segmentation)
	}
	result.ExtraInfo = strings.Join(extra, " ")
	return result, nil
}

// sanitizeString keeps only printable ASCII.
func sanitizeString(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 0x20 && c <= 0x7E {
			result = append(result, c)
		}
	}
	return string(result)
}

// buildReadPropertyRequest builds a ReadProperty request for a device property.
func buildReadPropertyRequest(deviceInstance uint32, propertyID, invokeID byte) []byte {
	objectID := (uint32(8) << 22) | (deviceInstance & 0x3FFFFF)
	return []byte{
		0x81, 0x0A, 0x00, 0x11, // BVLC
		0x01, 0x04, // NPDU (expecting reply)
		0x00, 0x05, invokeID, // APDU: Confirmed-REQ
		serviceReadProperty,
		0x0C, // Context tag 0 (Object ID)
		byte(objectID >> 24), byte(objectID >> 16), byte(objectID >> 8), byte(objectID),
		0x19, // Context tag 1 (Property ID)
		propertyID,
	}
}

// enrichWithReadProperty queries Model-Name and Firmware-Revision.
func enrichWithReadProperty(conn net.Conn, timeout time.Duration, deviceInstance uint32) (modelName, firmwareRev string) {
	if resp, err := udp.SendRecv(conn, buildReadPropertyRequest(deviceInstance, propModelName, 0x01), timeout); err == nil {
		modelName = parseReadPropertyAck(resp)
	}
	if resp, err := udp.SendRecv(conn, buildReadPropertyRequest(deviceInstance, propFirmwareRevision, 0x02), timeout); err == nil {
		firmwareRev = parseReadPropertyAck(resp)
	}
	return modelName, firmwareRev
}

// parseReadPropertyAck extracts a character-string value from a ReadProperty-ACK.
func parseReadPropertyAck(data []byte) string {
	if len(data) < 12 || data[0] != 0x81 || data[4] != 0x01 {
		return ""
	}
	control := data[5]
	offset := 6
	if control&0x20 != 0 {
		if len(data) < offset+3 {
			return ""
		}
		offset += 3 + int(data[offset+2])
	}
	if control&0x08 != 0 {
		if len(data) < offset+3 {
			return ""
		}
		offset += 3 + int(data[offset+2])
	}
	if control&0x20 != 0 {
		offset++
	}
	if len(data) < offset+3 {
		return ""
	}
	if data[offset]&0xF0 != 0x30 { // not a Complex-ACK
		return ""
	}
	offset += 3 // APDU header

	for offset < len(data)-1 {
		if data[offset] == 0x3E { // opening tag 3: property value
			offset++
			break
		}
		offset++
	}
	if offset >= len(data)-2 {
		return ""
	}
	if tag := data[offset]; tag != 0x75 && (tag&0xF0) != 0x70 {
		return ""
	}
	offset++
	if offset >= len(data) {
		return ""
	}
	strLen := int(data[offset])
	offset++
	if strLen == 0xFE && offset+1 < len(data) {
		strLen = int(data[offset])<<8 | int(data[offset+1])
		offset += 2
	}
	if offset >= len(data) || strLen <= 0 {
		return ""
	}
	// Skip the encoding byte (0x00 = ANSI).
	offset++
	strLen--
	if strLen <= 0 || offset+strLen > len(data) {
		return ""
	}
	return sanitizeString(string(data[offset : offset+strLen]))
}

// parseIAm parses a BACnet I-Am response.
func parseIAm(data []byte) (deviceInfo, bool) {
	var info deviceInfo
	if len(data) < 12 || data[0] != 0x81 {
		return info, false
	}
	if data[1] != 0x0A && data[1] != 0x0B {
		return info, false
	}
	if int(binary.BigEndian.Uint16(data[2:4])) != len(data) || data[4] != 0x01 {
		return info, false
	}

	control := data[5]
	offset := 6
	if control&0x20 != 0 {
		if len(data) < offset+3 {
			return info, false
		}
		offset += 3 + int(data[offset+2])
	}
	if control&0x08 != 0 {
		if len(data) < offset+3 {
			return info, false
		}
		offset += 3 + int(data[offset+2])
	}
	if control&0x20 != 0 {
		offset++
	}

	if len(data) < offset+2 || data[offset] != 0x10 || data[offset+1] != 0x00 {
		return info, false
	}
	offset += 2

	if len(data) < offset+11 || data[offset] != 0xC4 {
		return info, false
	}
	info.DeviceInstance = binary.BigEndian.Uint32(data[offset+1:offset+5]) & 0x3FFFFF
	offset += 5

	// Max APDU [1]
	if data[offset] != 0x21 && data[offset] != 0x22 {
		return info, false
	}
	if data[offset] == 0x21 {
		info.MaxAPDU = uint16(data[offset+1])
		offset += 2
	} else {
		if len(data) < offset+3 {
			return info, false
		}
		info.MaxAPDU = binary.BigEndian.Uint16(data[offset+1 : offset+3])
		offset += 3
	}

	// Segmentation [2]
	if data[offset] != 0x91 {
		return info, false
	}
	info.Segmentation = segmentationString(data[offset+1])
	offset += 2

	// Vendor ID [3]
	if data[offset] != 0x21 && data[offset] != 0x22 {
		return info, false
	}
	if data[offset] == 0x21 {
		info.VendorID = uint16(data[offset+1])
		offset += 2
	} else {
		if len(data) < offset+3 {
			return info, false
		}
		info.VendorID = binary.BigEndian.Uint16(data[offset+1 : offset+3])
		offset += 3
	}

	// Optional model name / firmware (character strings).
	for offset < len(data) {
		switch data[offset] {
		case 0x75:
			if len(data) < offset+2 {
				offset = len(data)
				continue
			}
			strLen := int(data[offset+1])
			if len(data) < offset+3+strLen {
				offset = len(data)
				continue
			}
			strData := string(data[offset+3 : offset+3+strLen])
			if info.ModelName == "" {
				info.ModelName = strData
			} else if info.FirmwareRev == "" {
				info.FirmwareRev = strData
			}
			offset += 3 + strLen
		case 0x2C:
			offset += 2
		default:
			offset = len(data)
		}
	}

	info.VendorName = getVendorName(info.VendorID)
	info.ModelName = sanitizeString(info.ModelName)
	info.FirmwareRev = sanitizeString(info.FirmwareRev)
	info.CPEs = generateCPE(info.VendorID, info.ModelName, info.FirmwareRev)
	return info, true
}

func segmentationString(v byte) string {
	switch v {
	case 0:
		return "both"
	case 1:
		return "transmit"
	case 2:
		return "receive"
	case 3:
		return "none"
	default:
		return fmt.Sprintf("unknown(%d)", v)
	}
}

// generateCPE builds a CPE 2.3 string for a known BACnet vendor.
func generateCPE(vendorID uint16, modelName, firmwareRev string) []string {
	vendorSlug := getVendorSlug(vendorID)
	if vendorSlug == "*" {
		return nil
	}
	modelSlug := "*"
	if modelName != "" {
		modelSlug = normalizeCPE(modelName)
	}
	firmwareSlug := "*"
	if firmwareRev != "" {
		firmwareSlug = normalizeCPE(firmwareRev)
	}
	return []string{fmt.Sprintf("cpe:2.3:h:%s:%s:%s:*:*:*:*:*:*:*", vendorSlug, modelSlug, firmwareSlug)}
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
