package dot1qenum

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	ethTypeVLAN = 0x8100
	ethTypeIPv4 = 0x0800
	ethTypeIPv6 = 0x86DD
	ethTypeARP  = 0x0806
	ipProtoICMP = 1
)

var broadcastMAC = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type formattedPacket struct {
	SrcMAC string
	DstMAC string
	Body   string
	IsICMP bool
}

func buildProbeFrame(srcMAC net.HardwareAddr, srcIP net.IP, payload string) []byte {
	const (
		priority = 7
		dei      = 0
		vlanID   = 1
	)
	tci := uint16(priority<<13 | dei<<12 | (vlanID & 0xfff))

	icmpPayload := []byte(payload)
	icmpLen := 8 + len(icmpPayload)
	ipLen := 20 + icmpLen
	total := 14 + 4 + ipLen

	frame := make([]byte, total)
	copy(frame[0:6], broadcastMAC[:])
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], ethTypeVLAN)
	binary.BigEndian.PutUint16(frame[14:16], tci)
	binary.BigEndian.PutUint16(frame[16:18], ethTypeIPv4)

	ip := frame[18:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	ip[8] = 64
	ip[9] = 1 // ICMP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], []byte{255, 255, 255, 255})

	icmp := ip[20:]
	icmp[0] = 8 // echo
	icmp[1] = 0
	icmp[4] = 0x42
	icmp[5] = 0x42
	copy(icmp[8:], icmpPayload)

	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))
	binary.BigEndian.PutUint16(icmp[2:4], icmpChecksum(srcIP, net.IPv4(255, 255, 255, 255), icmp))

	return frame
}

func formatPacket(frame []byte, strippedVLAN uint16) (formattedPacket, bool) {
	frame = normalizeL2Frame(frame, strippedVLAN)
	if off, ok := scanTaggedICMP(frame); ok {
		return formatFromOffsets(frame, off.vlanOff, off.ipOff, true)
	}

	srcMAC, dstMAC, macOK := extractMACs(frame)
	if !macOK {
		return formattedPacket{}, false
	}

	var lines []string
	lines = append(lines, "Linux cooked capture v1")

	l3Off, sllVLAN, ok := linkPayloadOffset(frame)
	if !ok {
		return formattedPacket{}, false
	}

	vlanLines, l3Off, hasVLAN := parseVLANTags(frame, l3Off, sllVLAN)
	if !hasVLAN {
		return formattedPacket{}, false
	}
	lines = append(lines, vlanLines...)

	isICMP := false
	et, payloadOff, ok := resolveInnerEthertype(frame, l3Off)
	if !ok {
		return formattedPacket{SrcMAC: srcMAC, DstMAC: dstMAC, Body: strings.Join(lines, "\n")}, true
	}

	switch et {
	case ethTypeIPv4:
		if ipLine, ok := parseIPv4Line(frame, payloadOff); ok {
			lines = append(lines, ipLine)
			isICMP = isICMPv4(frame, payloadOff)
		}
	case ethTypeIPv6:
		if ipLine, ok := parseIPv6Line(frame, payloadOff); ok {
			lines = append(lines, ipLine)
			isICMP = isICMPv6(frame, payloadOff)
		}
	case ethTypeARP:
		if ipLine, ok := parseARPIPLine(frame, payloadOff); ok {
			lines = append(lines, ipLine)
		}
	}

	return formattedPacket{
		SrcMAC: srcMAC,
		DstMAC: dstMAC,
		Body:   strings.Join(lines, "\n"),
		IsICMP: isICMP,
	}, true
}

type frameOffsets struct {
	vlanOff int
	ipOff   int
}

func formatFromOffsets(frame []byte, vlanOff, ipOff int, isICMP bool) (formattedPacket, bool) {
	srcMAC, dstMAC, macOK := extractMACs(frame)
	if !macOK {
		return formattedPacket{}, false
	}

	var lines []string
	lines = append(lines, "Linux cooked capture v1")

	if vlanOff >= 0 {
		if vlanLines, _, ok := parseVLANTags(frame, vlanOff, false); ok {
			lines = append(lines, vlanLines...)
		}
	}

	if ipLine, ok := parseIPv4Line(frame, ipOff); ok {
		lines = append(lines, ipLine)
	}

	return formattedPacket{
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
		case ethTypeVLAN:
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

func scanTaggedICMP(frame []byte) (frameOffsets, bool) {
	limit := len(frame) - 28
	for i := 0; i <= limit; i++ {
		if binary.BigEndian.Uint16(frame[i:i+2]) != ethTypeVLAN {
			continue
		}
		if i+18 > len(frame) {
			continue
		}
		if binary.BigEndian.Uint16(frame[i+4:i+6]) != ethTypeIPv4 {
			continue
		}
		ipOff := i + 6
		if !isICMPv4(frame, ipOff) {
			continue
		}
		return frameOffsets{vlanOff: i + 2, ipOff: ipOff}, true
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

func formatMAC(mac []byte) string {
	if len(mac) != 6 {
		return "unknown"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func injectVLANTag(frame []byte, tci uint16) []byte {
	if len(frame) < 14 || isSLL(frame) {
		return frame
	}
	if _, off, has := parseVLANTags(frame, 12, false); has && off > 12 {
		return frame
	}
	if _, ok := scanTaggedICMP(frame); ok {
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
		if et != ethTypeVLAN && et != 0x88a8 {
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
	if next == ethTypeVLAN || next == 0x88a8 {
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

func parseIPv4Line(frame []byte, off int) (string, bool) {
	if off+20 > len(frame) {
		return "", false
	}
	ver := frame[off] >> 4
	if ver != 4 {
		return "", false
	}
	src := net.IP(frame[off+12 : off+16])
	dst := net.IP(frame[off+16 : off+20])
	return fmt.Sprintf("Internet Protocol Version %d, Src: %s, Dst: %s", ver, src, dst), true
}

func parseIPv6Line(frame []byte, off int) (string, bool) {
	if off+40 > len(frame) {
		return "", false
	}
	ver := frame[off] >> 4
	if ver != 6 {
		return "", false
	}
	src := net.IP(frame[off+8 : off+24])
	dst := net.IP(frame[off+24 : off+40])
	return fmt.Sprintf("Internet Protocol Version %d, Src: %s, Dst: %s", ver, src, dst), true
}

func parseARPIPLine(frame []byte, off int) (string, bool) {
	if off+28 > len(frame) {
		return "", false
	}
	if binary.BigEndian.Uint16(frame[off+2:off+4]) != 1 ||
		binary.BigEndian.Uint16(frame[off+4:off+6]) != 0x0800 {
		return "", false
	}
	src := net.IP(frame[off+14 : off+18])
	dst := net.IP(frame[off+24 : off+28])
	return fmt.Sprintf("Internet Protocol Version 4, Src: %s, Dst: %s", src, dst), true
}

func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func icmpChecksum(src, dst net.IP, icmp []byte) uint16 {
	pseudo := make([]byte, 12+len(icmp))
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[9] = 1
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(icmp)))
	copy(pseudo[12:], icmp)
	return ipChecksum(pseudo)
}
