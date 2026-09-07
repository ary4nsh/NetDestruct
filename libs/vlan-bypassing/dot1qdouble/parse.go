package dot1qdouble

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

type FormattedPacket struct {
	SrcMAC string
	DstMAC string
	Body   string
	IsICMP bool
}

func FormatPacket(frame []byte, strippedVLAN uint16) (FormattedPacket, bool) {
	frame = normalizeL2Frame(frame, strippedVLAN)
	if off, ok := scanTaggedL3(frame); ok {
		return formatFromOffsets(frame, off.vlanOff, off.l3Off, off.isICMP)
	}

	srcMAC, dstMAC, macOK := extractMACs(frame)
	if !macOK {
		return FormattedPacket{}, false
	}

	var lines []string
	lines = append(lines, "Linux cooked capture v1")

	l3Off, sllVLAN, ok := linkPayloadOffset(frame)
	if !ok {
		return FormattedPacket{}, false
	}

	vlanLines, l3Off, hasVLAN := parseVLANTags(frame, l3Off, sllVLAN)
	if !hasVLAN {
		return FormattedPacket{}, false
	}
	lines = append(lines, vlanLines...)

	isICMP := false
	et, payloadOff, ok := resolveInnerEthertype(frame, l3Off)
	if !ok {
		return FormattedPacket{SrcMAC: srcMAC, DstMAC: dstMAC, Body: strings.Join(lines, "\n")}, true
	}

	switch et {
	case ethTypeIPv4:
		if ipLines, icmp, ok := parseIPv4(frame, payloadOff); ok {
			lines = append(lines, ipLines...)
			isICMP = icmp
		}
	case ethTypeIPv6:
		if ipLines, icmp, ok := parseIPv6(frame, payloadOff); ok {
			lines = append(lines, ipLines...)
			isICMP = icmp
		}
	case ethTypeARP:
		if arpLine, ok := parseARP(frame, payloadOff); ok {
			lines = append(lines, arpLine)
		}
	default:
		if name := ethertypeName(et); name != "" {
			lines = append(lines, fmt.Sprintf("%s (0x%04x)", name, et))
		} else if llcLines, ok := parseLLCSNAP(frame, l3Off); ok {
			lines = append(lines, llcLines...)
		}
	}

	return FormattedPacket{
		SrcMAC: srcMAC,
		DstMAC: dstMAC,
		Body:   strings.Join(lines, "\n"),
		IsICMP: isICMP,
	}, true
}

type frameOffsets struct {
	vlanOff int
	l3Off   int
	isICMP  bool
}

func formatFromOffsets(frame []byte, vlanOff, l3Off int, isICMP bool) (FormattedPacket, bool) {
	srcMAC, dstMAC, macOK := extractMACs(frame)
	if !macOK {
		return FormattedPacket{}, false
	}

	var lines []string
	lines = append(lines, "Linux cooked capture v1")

	if vlanOff >= 0 {
		if vlanLines, _, ok := parseVLANTags(frame, vlanOff, false); ok {
			lines = append(lines, vlanLines...)
		}
	}

	if ipLines, icmp, ok := parseIPv4(frame, l3Off); ok {
		lines = append(lines, ipLines...)
		isICMP = icmp
	}

	return FormattedPacket{
		SrcMAC: srcMAC,
		DstMAC: dstMAC,
		Body:   strings.Join(lines, "\n"),
		IsICMP: isICMP,
	}, true
}

func normalizeL2Frame(frame []byte, strippedVLAN uint16) []byte {
	if isSLL(frame) && len(frame) >= 16 {
		proto := binary.BigEndian.Uint16(frame[14:16])
		payload := append([]byte{}, frame[16:]...)
		pktType := binary.BigEndian.Uint16(frame[0:2])
		src := append([]byte{}, frame[6:12]...)
		dst := broadcastMAC
		if pktType != 4 {
			dst = broadcastMAC
		}

		switch proto {
		case ethTypeVLAN, ethTypeQinQ:
			out := make([]byte, 12+2+len(payload))
			copy(out[0:6], dst[:])
			copy(out[6:12], src)
			out[12] = 0x81
			out[13] = 0x00
			copy(out[14:], payload)
			frame = out
		case ethTypeIPv4, ethTypeIPv6, ethTypeARP:
			out := make([]byte, 14+len(payload))
			copy(out[0:6], dst[:])
			copy(out[6:12], src)
			copy(out[14:], payload)
			frame = out
		}
	}

	if strippedVLAN != 0 {
		frame = injectVLANTag(frame, strippedVLAN)
	}
	return frame
}

func scanTaggedL3(frame []byte) (frameOffsets, bool) {
	limit := len(frame) - 28
	for i := 0; i <= limit; i++ {
		et := binary.BigEndian.Uint16(frame[i : i+2])
		if et != ethTypeVLAN && et != ethTypeQinQ {
			continue
		}
		off := i + 2
		tags := 1
		for off+4 <= len(frame) {
			inner := binary.BigEndian.Uint16(frame[off+2 : off+4])
			if inner != ethTypeVLAN && inner != ethTypeQinQ {
				break
			}
			tags++
			off += 4
		}
		if off+6 > len(frame) {
			continue
		}
		l3 := off + 4
		if binary.BigEndian.Uint16(frame[l3-2:l3]) != ethTypeIPv4 {
			continue
		}
		if !isICMPv4(frame, l3) {
			continue
		}
		return frameOffsets{vlanOff: i, l3Off: l3, isICMP: true}, true
	}
	return frameOffsets{}, false
}

func isICMPv4(frame []byte, ipOff int) bool {
	if ipOff+20 > len(frame) {
		return false
	}
	if frame[ipOff]>>4 != 4 {
		return false
	}
	ihl := int(frame[ipOff]&0x0f) * 4
	if ihl < 20 || ipOff+ihl > len(frame) {
		return false
	}
	return frame[ipOff+9] == ipProtoICMP
}

func isICMPv6(frame []byte, ipOff int) bool {
	if ipOff+40 > len(frame) {
		return false
	}
	return frame[ipOff]>>4 == 6 && frame[ipOff+6] == 58
}

func extractMACs(frame []byte) (src, dst string, ok bool) {
	if len(frame) < 12 {
		return "", "", false
	}
	return formatMAC(frame[6:12]), formatMAC(frame[0:6]), true
}

func injectVLANTag(frame []byte, tci uint16) []byte {
	if len(frame) < 14 || isSLL(frame) {
		return frame
	}
	if _, off, has := parseVLANTags(frame, 12, false); has && off > 12 {
		return frame
	}
	if _, ok := scanTaggedL3(frame); ok {
		return frame
	}
	out := make([]byte, len(frame)+4)
	copy(out[0:12], frame[0:12])
	binary.BigEndian.PutUint16(out[12:14], ethTypeVLAN)
	binary.BigEndian.PutUint16(out[14:16], tci)
	copy(out[16:], frame[12:])
	return out
}

func linkPayloadOffset(frame []byte) (off int, sllVLAN bool, ok bool) {
	if len(frame) < 14 {
		return 0, false, false
	}
	return 12, false, true
}

func parseVLANTags(frame []byte, off int, sllVLAN bool) ([]string, int, bool) {
	if sllVLAN {
		if off+2 > len(frame) {
			return nil, off, false
		}
		pri, dei, id, _ := decodeTCI(binary.BigEndian.Uint16(frame[off : off+2]))
		return []string{vlanLine(pri, dei, id)}, off + 2, true
	}

	var lines []string
	start := off
	for off+4 <= len(frame) {
		et := binary.BigEndian.Uint16(frame[off : off+2])
		if et != ethTypeVLAN && et != ethTypeQinQ {
			break
		}
		pri, dei, id, _ := decodeTCI(binary.BigEndian.Uint16(frame[off+2 : off+4]))
		lines = append(lines, vlanLine(pri, dei, id))
		off += 4
	}
	if len(lines) > 0 {
		return lines, off, true
	}

	if off+4 <= len(frame) {
		tci := binary.BigEndian.Uint16(frame[off : off+2])
		next := binary.BigEndian.Uint16(frame[off+2 : off+4])
		if looksLikeVLANTCI(tci, next) {
			pri, dei, id, _ := decodeTCI(tci)
			return []string{vlanLine(pri, dei, id)}, off + 2, true
		}
	}

	return nil, start, false
}

func looksLikeVLANTCI(tci, next uint16) bool {
	if next == ethTypeVLAN || next == ethTypeQinQ {
		return true
	}
	if next < 0x0800 {
		return true
	}
	switch next {
	case ethTypeIPv4, ethTypeIPv6, ethTypeARP, 0x2000, 0x2003, 0x2004, 0x010b, 0x9000:
		return true
	}
	return false
}

func resolveInnerEthertype(frame []byte, off int) (uint16, int, bool) {
	if off+2 > len(frame) {
		return 0, 0, false
	}
	et := binary.BigEndian.Uint16(frame[off : off+2])
	if et >= 0x0800 {
		return et, off + 2, true
	}

	if off+8 <= len(frame) && frame[off+2] == 0xaa && frame[off+3] == 0xaa && frame[off+4] == 0x03 {
		pid := binary.BigEndian.Uint16(frame[off+6 : off+8])
		return pid, off + 8, true
	}

	if off+4 <= len(frame) {
		next := binary.BigEndian.Uint16(frame[off+2 : off+4])
		if next >= 0x0800 {
			return next, off + 4, true
		}
	}

	return 0, 0, false
}

func isSLL(frame []byte) bool {
	if len(frame) < 16 {
		return false
	}
	pktType := binary.BigEndian.Uint16(frame[0:2])
	if pktType > 4 {
		return false
	}
	return binary.BigEndian.Uint16(frame[2:4]) == 1 &&
		binary.BigEndian.Uint16(frame[4:6]) == 6
}

func decodeTCI(tci uint16) (pri, dei, id uint16, ok bool) {
	return (tci >> 13) & 0x7, (tci >> 12) & 1, tci & 0x0fff, true
}

func vlanLine(pri, dei, id uint16) string {
	return fmt.Sprintf("802.1Q Virtual LAN, PRI: %d, DEI: %d and ID: %d", pri, dei, id)
}

func parseIPv4(frame []byte, off int) ([]string, bool, bool) {
	if off+20 > len(frame) {
		return nil, false, false
	}
	ver := frame[off] >> 4
	if ver != 4 {
		return nil, false, false
	}
	ihl := int(frame[off]&0x0f) * 4
	if ihl < 20 || off+ihl > len(frame) {
		return nil, false, false
	}
	src := net.IP(frame[off+12 : off+16])
	dst := net.IP(frame[off+16 : off+20])
	proto := frame[off+9]
	lines := []string{
		fmt.Sprintf("Internet Protocol Version %d, Src: %s, Dst: %s", ver, src, dst),
		fmt.Sprintf("    Version: %d", ver),
		fmt.Sprintf("    Header Length: %d bytes", ihl),
		fmt.Sprintf("    TTL: %d", frame[off+8]),
		fmt.Sprintf("    Protocol: %s (%d)", ipProtoName(proto), proto),
	}

	isICMP := proto == ipProtoICMP
	if isICMP && off+ihl+8 <= len(frame) {
		icmpOff := off + ihl
		lines = append(lines, parseICMPLines(frame[icmpOff:])...)
	}
	return lines, isICMP, true
}

func parseIPv6(frame []byte, off int) ([]string, bool, bool) {
	if off+40 > len(frame) {
		return nil, false, false
	}
	ver := frame[off] >> 4
	if ver != 6 {
		return nil, false, false
	}
	src := net.IP(frame[off+8 : off+24])
	dst := net.IP(frame[off+24 : off+40])
	next := frame[off+6]
	lines := []string{
		fmt.Sprintf("Internet Protocol Version %d, Src: %s, Dst: %s", ver, src, dst),
		fmt.Sprintf("    Version: %d", ver),
		fmt.Sprintf("    Next Header: %s (%d)", ipProtoName(next), next),
	}
	isICMP := next == 58
	if isICMP && off+48 <= len(frame) {
		lines = append(lines, parseICMPv6Lines(frame[off+40:])...)
	}
	return lines, isICMP, true
}

func parseARP(frame []byte, off int) (string, bool) {
	if off+28 > len(frame) {
		return "", false
	}
	if binary.BigEndian.Uint16(frame[off:off+2]) != 0x0001 ||
		binary.BigEndian.Uint16(frame[off+2:off+4]) != ethTypeIPv4 {
		return "", false
	}
	opcode := binary.BigEndian.Uint16(frame[off+6 : off+8])
	srcMAC := formatMAC(frame[off+8 : off+14])
	srcIP := net.IP(frame[off+14 : off+18])
	dstMAC := formatMAC(frame[off+18 : off+24])
	dstIP := net.IP(frame[off+24 : off+28])
	return fmt.Sprintf("Address Resolution Protocol (%s), Src MAC: %s, Src IP: %s, Dst MAC: %s, Dst IP: %s",
		arpOpName(opcode), srcMAC, srcIP, dstMAC, dstIP), true
}

func parseICMPLines(icmp []byte) []string {
	if len(icmp) < 8 {
		return nil
	}
	typ, code := icmp[0], icmp[1]
	id := binary.BigEndian.Uint16(icmp[4:6])
	seq := binary.BigEndian.Uint16(icmp[6:8])
	lines := []string{
		fmt.Sprintf("Internet Control Message Protocol, Type: %d (%s), Code: %d",
			typ, icmpTypeName(typ), code),
		fmt.Sprintf("    Identifier: 0x%04x (%d)", id, id),
		fmt.Sprintf("    Sequence Number: %d", seq),
	}
	if len(icmp) > 8 {
		payload := string(icmp[8:])
		if printable(payload) != "" {
			lines = append(lines, fmt.Sprintf("    Data: %s", printable(payload)))
		}
	}
	return lines
}

func parseICMPv6Lines(icmp []byte) []string {
	if len(icmp) < 4 {
		return nil
	}
	typ, code := icmp[0], icmp[1]
	lines := []string{
		fmt.Sprintf("Internet Control Message Protocol v6, Type: %d (%s), Code: %d",
			typ, icmpv6TypeName(typ), code),
	}
	if len(icmp) > 8 {
		payload := string(icmp[8:])
		if printable(payload) != "" {
			lines = append(lines, fmt.Sprintf("    Data: %s", printable(payload)))
		}
	}
	return lines
}

func parseLLCSNAP(frame []byte, off int) ([]string, bool) {
	if off+8 > len(frame) {
		return nil, false
	}
	if frame[off] != 0xaa || frame[off+1] != 0xaa || frame[off+2] != 0x03 {
		return nil, false
	}
	oui := fmt.Sprintf("%02x:%02x:%02x", frame[off+3], frame[off+4], frame[off+5])
	pid := binary.BigEndian.Uint16(frame[off+6 : off+8])
	name := ethertypeName(pid)
	if name == "" {
		name = fmt.Sprintf("0x%04x", pid)
	}
	return []string{
		fmt.Sprintf("Logical-Link Control (LLC), DSAP: 0xaa, SSAP: 0xaa, Control: 0x03"),
		fmt.Sprintf("    Organization Code: %s", oui),
		fmt.Sprintf("    Protocol ID: %s", name),
	}, true
}

func ethertypeName(et uint16) string {
	switch et {
	case ethTypeIPv4:
		return "IPv4"
	case ethTypeIPv6:
		return "IPv6"
	case ethTypeARP:
		return "ARP"
	case ethTypeVLAN:
		return "802.1Q"
	case ethTypeQinQ:
		return "802.1ad"
	case 0x2000:
		return "CDP"
	case 0x2003:
		return "VTP"
	case 0x2004:
		return "DTP"
	case 0x010b:
		return "PVST"
	case 0x9000:
		return "Loop"
	case 0x888e:
		return "EAPOL"
	default:
		return ""
	}
}

func ipProtoName(p byte) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	case 89:
		return "OSPF"
	default:
		return "Unknown"
	}
}

func icmpTypeName(t byte) string {
	switch t {
	case 0:
		return "Echo Reply"
	case 3:
		return "Destination Unreachable"
	case 5:
		return "Redirect"
	case 8:
		return "Echo (ping) request"
	case 11:
		return "Time Exceeded"
	default:
		return "Unknown"
	}
}

func icmpv6TypeName(t byte) string {
	switch t {
	case 128:
		return "Echo (ping) request"
	case 129:
		return "Echo Reply"
	default:
		return "Unknown"
	}
}

func arpOpName(op uint16) string {
	switch op {
	case 1:
		return "request"
	case 2:
		return "reply"
	default:
		return fmt.Sprintf("opcode %d", op)
	}
}

func printable(s string) string {
	s = strings.TrimRight(s, "\x00")
	if strings.TrimSpace(s) == "" {
		return ""
	}
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return ""
		}
	}
	return s
}
