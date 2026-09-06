package vtpdelete

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

func parseLearnedVTP(frame []byte) (learnedVTP, bool) {
	off, ok := vtpPayloadOffset(frame)
	if !ok || off+4 > len(frame) {
		return learnedVTP{}, false
	}
	l := learnedVTP{
		Version: frame[off],
		Code:    frame[off+1],
	}
	switch l.Code {
	case vtpCodeSummary, vtpCodeSubset:
	default:
		return learnedVTP{}, false
	}
	if l.Code == vtpCodeSummary {
		l.Followers = frame[off+2]
	} else {
		l.Seq = frame[off+2]
	}
	domLen := int(frame[off+3])
	if domLen > vtpDomainSize {
		domLen = vtpDomainSize
	}
	l.DomLen = domLen
	if off+4+domLen > len(frame) {
		return learnedVTP{}, false
	}
	l.Domain = append([]byte{}, frame[off+4:off+4+domLen]...)
	revOff := off + 36
	if revOff+4 > len(frame) {
		return learnedVTP{}, false
	}
	l.Revision = binary.BigEndian.Uint32(frame[revOff : revOff+4])
	if l.Code == vtpCodeSummary {
		if off+44 <= len(frame) {
			l.Updater = binary.BigEndian.Uint32(frame[off+40 : off+44])
		}
		if off+56 <= len(frame) {
			copy(l.Timestamp[:], frame[off+44:off+56])
		}
	} else if off+vtpSubsetHdr < len(frame) {
		l.VlanData = append([]byte{}, frame[off+vtpSubsetHdr:]...)
	}
	return l, true
}

func vtpPayloadOffset(frame []byte) (int, bool) {
	if len(frame) < 22 {
		return 0, false
	}
	off := 12
	for off+4 <= len(frame) {
		t := binary.BigEndian.Uint16(frame[off : off+2])
		if t == 0x8100 || t == 0x88a8 {
			off += 4
			continue
		}
		break
	}
	if off+2 > len(frame) {
		return 0, false
	}
	ethLen := binary.BigEndian.Uint16(frame[off : off+2])
	if ethLen >= 0x0600 {
		return 0, false
	}
	llcOff := off + 2
	if llcOff+8 > len(frame) {
		return 0, false
	}
	if frame[llcOff] != 0xaa || frame[llcOff+1] != 0xaa || frame[llcOff+2] != 0x03 {
		return 0, false
	}
	if frame[llcOff+3] != 0x00 || frame[llcOff+4] != 0x00 || frame[llcOff+5] != 0x0c || frame[llcOff+6] != 0x20 || frame[llcOff+7] != 0x03 {
		return 0, false
	}
	_ = ethLen
	return llcOff + 8, true
}

func formatVTPFrame(frame []byte, iface string, frameNum int) (srcMAC string, body string, ok bool) {
	if len(frame) < 12 {
		return "", "", false
	}
	off, ok := vtpPayloadOffset(frame)
	if !ok {
		return "", "", false
	}
	srcMAC = formatMAC(frame[6:12])
	var b strings.Builder
	bits := len(frame) * 8
	b.WriteString(fmt.Sprintf("Frame %d: Packet, %d bytes on wire (%d bits), %d bytes captured (%d bits) on interface %s, id 0\n",
		frameNum, len(frame), bits, len(frame), bits, iface))
	b.WriteString("IEEE 802.3 Ethernet \n")
	b.WriteString("Logical-Link Control\n")
	b.WriteString(formatVTPPayload(frame[off:]))
	return srcMAC, strings.TrimRight(b.String(), "\n"), true
}

func formatVTPPayload(data []byte) string {
	if len(data) < 4 {
		return "VLAN Trunking Protocol (truncated)"
	}
	var b strings.Builder
	b.WriteString("VLAN Trunking Protocol\n")
	b.WriteString(fmt.Sprintf("    Version: 0x%02x\n", data[0]))
	code := data[1]
	b.WriteString(fmt.Sprintf("    Code: %s (0x%02x)\n", vtpCodeName(code), code))

	switch code {
	case vtpCodeSummary:
		if len(data) < vtpSummarySize {
			b.WriteString("    (truncated Summary Advertisement)\n")
			return strings.TrimRight(b.String(), "\n")
		}
		b.WriteString(fmt.Sprintf("    Followers: %d\n", data[2]))
		domLen := int(data[3])
		if domLen > vtpDomainSize {
			domLen = vtpDomainSize
		}
		b.WriteString(fmt.Sprintf("    Management Domain Length: %d\n", domLen))
		b.WriteString(fmt.Sprintf("    Management Domain: %s\n", printable(data[4:4+domLen])))
		b.WriteString(fmt.Sprintf("    Configuration Revision Number: %d\n", binary.BigEndian.Uint32(data[36:40])))
		updater := net.IP(data[40:44])
		b.WriteString(fmt.Sprintf("    Updater Identity: %s\n", updater))
		b.WriteString(fmt.Sprintf("    Update Timestamp: %s\n", formatVTPTimestamp(data[44:56])))
		b.WriteString(fmt.Sprintf("    MD5 Digest: %x\n", data[56:72]))

	case vtpCodeSubset:
		if len(data) < vtpSubsetHdr {
			b.WriteString("    (truncated Subset Advertisement)\n")
			return strings.TrimRight(b.String(), "\n")
		}
		b.WriteString(fmt.Sprintf("    Sequence Number: %d\n", data[2]))
		domLen := int(data[3])
		if domLen > vtpDomainSize {
			domLen = vtpDomainSize
		}
		b.WriteString(fmt.Sprintf("    Management Domain Length: %d\n", domLen))
		b.WriteString(fmt.Sprintf("    Management Domain: %s\n", printable(data[4:4+domLen])))
		b.WriteString(fmt.Sprintf("    Configuration Revision Number: %d\n", binary.BigEndian.Uint32(data[36:40])))
		b.WriteString(formatVLANInfos(data[vtpSubsetHdr:]))

	case vtpCodeRequest:
		if len(data) < 38 {
			b.WriteString("    (truncated Advertisement Request)\n")
			return strings.TrimRight(b.String(), "\n")
		}
		domLen := int(data[3])
		if domLen > vtpDomainSize {
			domLen = vtpDomainSize
		}
		b.WriteString(fmt.Sprintf("    Management Domain Length: %d\n", domLen))
		b.WriteString(fmt.Sprintf("    Management Domain: %s\n", printable(data[4:4+domLen])))
		b.WriteString(fmt.Sprintf("    Start Value: %d\n", binary.BigEndian.Uint16(data[36:38])))

	case vtpCodeJoin:
		if len(data) < 40 {
			b.WriteString("    (truncated Join/Prune Message)\n")
			return strings.TrimRight(b.String(), "\n")
		}
		domLen := int(data[3])
		if domLen > vtpDomainSize {
			domLen = vtpDomainSize
		}
		b.WriteString(fmt.Sprintf("    Management Domain Length: %d\n", domLen))
		b.WriteString(fmt.Sprintf("    Management Domain: %s\n", printable(data[4:4+domLen])))
		firstVID := binary.BigEndian.Uint16(data[36:38])
		lastVID := binary.BigEndian.Uint16(data[38:40])
		b.WriteString(fmt.Sprintf("    Pruning First VLAN ID: %d\n", firstVID))
		b.WriteString(fmt.Sprintf("    Pruning Last VLAN ID: %d\n", lastVID))
		if len(data) > 40 {
			b.WriteString(formatVTPPruningBitmap(data[40:], firstVID))
		}

	default:
		b.WriteString("    Unrecognized VTP message\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatVLANInfos(data []byte) string {
	var b strings.Builder
	off := 0
	for off < len(data) {
		if off+1 >= len(data) {
			break
		}
		infoLen := int(data[off])
		if infoLen == 0 || off+infoLen > len(data) {
			break
		}
		chunk := data[off : off+infoLen]
		b.WriteString(formatVLANInfo(chunk))
		off += infoLen
	}
	return b.String()
}

func formatVLANInfo(v []byte) string {
	if len(v) < 12 {
		return "    VLAN Information (truncated)\n"
	}
	status := v[1]
	vlanType := v[2]
	nameLen := int(v[3])
	vlanID := binary.BigEndian.Uint16(v[4:6])
	mtu := binary.BigEndian.Uint16(v[6:8])
	dot10 := binary.BigEndian.Uint32(v[8:12])
	alignedName := 4 * ((nameLen + 3) / 4)
	nameEnd := 12 + alignedName
	name := ""
	if nameEnd <= len(v) {
		name = printable(v[12:nameEnd])
	}
	var b strings.Builder
	b.WriteString("    VLAN Information\n")
	b.WriteString(fmt.Sprintf("        VLAN Information Length: %d\n", v[0]))
	statusLine := fmt.Sprintf("        Status: 0x%02x", status)
	if status&0x01 != 0 {
		statusLine += " (VLAN suspended)"
	}
	b.WriteString(statusLine + "\n")
	b.WriteString(fmt.Sprintf("        VLAN Type: %s (0x%02x)\n", vlanTypeName(vlanType), vlanType))
	b.WriteString(fmt.Sprintf("        VLAN Name Length: %d\n", nameLen))
	b.WriteString(fmt.Sprintf("        ISL VLAN ID: 0x%04x\n", vlanID))
	b.WriteString(fmt.Sprintf("        MTU Size: %d\n", mtu))
	b.WriteString(fmt.Sprintf("        802.10 Index: 0x%08x\n", dot10))
	b.WriteString(fmt.Sprintf("        VLAN Name: %s\n", name))
	if nameEnd < len(v) {
		b.WriteString(formatVLANTLVs(v[nameEnd:]))
	}
	return b.String()
}

func formatVLANTLVs(data []byte) string {
	var b strings.Builder
	off := 0
	for off+2 <= len(data) {
		typ := data[off]
		length := int(data[off+1])
		valEnd := off + 2 + length*2
		if valEnd > len(data) {
			break
		}
		value := data[off+2 : valEnd]
		b.WriteString(formatVLANTLV(typ, length, value))
		off = valEnd
	}
	return b.String()
}

func formatVLANTLV(typ byte, length int, value []byte) string {
	name := vlanTLVName(typ)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("        %s\n", name))
	b.WriteString(fmt.Sprintf("            Type: %s (0x%02x)\n", name, typ))
	b.WriteString(fmt.Sprintf("            Length: %d\n", length))
	if length == 0 {
		return b.String()
	}
	switch typ {
	case 0x01:
		if len(value) >= 2 {
			v := binary.BigEndian.Uint16(value[:2])
			b.WriteString(fmt.Sprintf("            Source-Routing Ring Number: 0x%04x\n", v))
		}
	case 0x02:
		if len(value) >= 2 {
			v := binary.BigEndian.Uint16(value[:2])
			b.WriteString(fmt.Sprintf("            Source-Routing Bridge Number: 0x%04x\n", v))
		}
	case 0x03:
		if len(value) >= 2 {
			v := binary.BigEndian.Uint16(value[:2])
			b.WriteString(fmt.Sprintf("            Spanning-Tree Protocol Type: %s (0x%04x)\n", stpTypeName(uint16(v)), v))
		}
	case 0x04:
		if len(value) >= 2 {
			v := binary.BigEndian.Uint16(value[:2])
			b.WriteString(fmt.Sprintf("            Parent VLAN: 0x%04x\n", v))
		}
	case 0x05:
		if len(value) >= 2 {
			v := binary.BigEndian.Uint16(value[:2])
			b.WriteString(fmt.Sprintf("            Translationally Bridged VLANs: 0x%04x\n", v))
		}
	case 0x06:
		if len(value) >= 2 {
			v := binary.BigEndian.Uint16(value[:2])
			b.WriteString(fmt.Sprintf("            Pruning: %s (0x%04x)\n", pruningName(uint16(v)), v))
		}
	case 0x07:
		if len(value) >= 2 {
			v := binary.BigEndian.Uint16(value[:2])
			b.WriteString(fmt.Sprintf("            Bridge Type: %s (0x%04x)\n", bridgeTypeName(uint16(v)), v))
		}
	case 0x08:
		if len(value) >= 2 {
			v := binary.BigEndian.Uint16(value[:2])
			b.WriteString(fmt.Sprintf("            Max ARE Hop Count: 0x%04x\n", v))
		}
	case 0x09:
		if len(value) >= 2 {
			v := binary.BigEndian.Uint16(value[:2])
			b.WriteString(fmt.Sprintf("            Max STE Hop Count: 0x%04x\n", v))
		}
	case 0x0a:
		if len(value) >= 2 {
			v := binary.BigEndian.Uint16(value[:2])
			b.WriteString(fmt.Sprintf("            Backup CRF Mode: %s (0x%04x)\n", backupCRFName(uint16(v)), v))
		}
	default:
		b.WriteString(fmt.Sprintf("            Data: %x\n", value))
	}
	return b.String()
}

func formatVTPPruningBitmap(data []byte, firstVID uint16) string {
	var b strings.Builder
	b.WriteString("    Advertised active (i.e. not pruned) VLANs\n")
	vid := firstVID
	for _, bitmap := range data {
		for shift := 0; shift < 8; shift++ {
			if bitmap&(0x80>>shift) != 0 {
				b.WriteString(fmt.Sprintf("        Active VLAN ID: %d\n", vid))
			}
			vid++
		}
	}
	return b.String()
}

func vtpCodeName(c byte) string {
	switch c {
	case vtpCodeSummary:
		return "Summary Advertisement"
	case vtpCodeSubset:
		return "Subset Advertisement"
	case vtpCodeRequest:
		return "Advertisement Request"
	case vtpCodeJoin:
		return "Join"
	default:
		return fmt.Sprintf("Unknown (%d)", c)
	}
}

func stpTypeName(v uint16) string {
	switch v {
	case 1:
		return "SRT"
	case 2:
		return "SRB"
	case 3:
		return "Auto"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}

func pruningName(v uint16) string {
	switch v {
	case 1:
		return "Enabled"
	case 2:
		return "Disabled"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}

func bridgeTypeName(v uint16) string {
	switch v {
	case 1:
		return "SRT"
	case 2:
		return "SRB"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}

func backupCRFName(v uint16) string {
	switch v {
	case 1:
		return "TrCRF is configured as a backup"
	case 2:
		return "TrCRF is not configured as a backup"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}

func vlanStatusName(s byte) string {
	switch s {
	case 0x00:
		return "VLAN active"
	case 0x01:
		return "VLAN deleted"
	case 0x02:
		return "Delete all VLANs"
	default:
		if s&0x01 != 0 {
			return "VLAN suspended"
		}
		return fmt.Sprintf("Unknown (0x%02x)", s)
	}
}

func vlanTypeName(t byte) string {
	switch t {
	case 0x01:
		return "Ethernet"
	case 0x02:
		return "FDDI"
	case 0x03:
		return "TrCRF"
	case 0x04:
		return "FDDI-net"
	case 0x05:
		return "TrBRF"
	default:
		return fmt.Sprintf("Unknown (0x%02x)", t)
	}
}

func vlanTLVName(t byte) string {
	switch t {
	case 0x01:
		return "Source-Routing Ring Number"
	case 0x02:
		return "Source-Routing Bridge Number"
	case 0x03:
		return "Spanning-Tree Protocol Type"
	case 0x04:
		return "Parent VLAN"
	case 0x05:
		return "Translationally Bridged VLANs"
	case 0x06:
		return "Pruning"
	case 0x07:
		return "Bridge Type"
	case 0x08:
		return "Max ARE Hop Count"
	case 0x09:
		return "Max STE Hop Count"
	case 0x0a:
		return "Backup CRF Mode"
	default:
		return "Unknown"
	}
}

func formatVTPTimestamp(ts []byte) string {
	if len(ts) < 12 {
		return string(ts)
	}
	s := string(ts)
	if len(s) == 12 {
		return fmt.Sprintf("%s-%s-%s %s:%s:%s", s[0:2], s[2:4], s[4:6], s[6:8], s[8:10], s[10:12])
	}
	return s
}

func printable(b []byte) string {
	return strings.TrimRight(string(b), "\x00")
}
