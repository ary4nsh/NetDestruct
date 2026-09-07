package dot1qdouble

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	ethTypeVLAN = 0x8100
	ethTypeQinQ = 0x88a8
	ethTypeIPv4 = 0x0800
	ethTypeIPv6 = 0x86DD
	ethTypeARP  = 0x0806
	ipProtoICMP = 1
)

var broadcastMAC = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func buildDoubleTagFrame(srcMAC net.HardwareAddr, srcIP net.IP, srcVLAN, dstVLAN int, payload string) []byte {
	const (
		priority = 7
		dei      = 0
	)
	outerTCI := uint16(priority<<13 | dei<<12 | (uint16(srcVLAN) & 0xfff))
	innerTCI := uint16(priority<<13 | dei<<12 | (uint16(dstVLAN) & 0xfff))

	icmpPayload := []byte(payload)
	icmpLen := 8 + len(icmpPayload)
	ipLen := 20 + icmpLen
	total := 14 + 4 + 4 + ipLen

	frame := make([]byte, total)
	copy(frame[0:6], broadcastMAC[:])
	copy(frame[6:12], srcMAC)

	binary.BigEndian.PutUint16(frame[12:14], ethTypeVLAN)
	binary.BigEndian.PutUint16(frame[14:16], outerTCI)
	binary.BigEndian.PutUint16(frame[16:18], ethTypeVLAN)
	binary.BigEndian.PutUint16(frame[18:20], innerTCI)
	binary.BigEndian.PutUint16(frame[20:22], ethTypeIPv4)

	ip := frame[22:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	ip[8] = 64
	ip[9] = ipProtoICMP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], []byte{255, 255, 255, 255})

	icmp := ip[20:]
	icmp[0] = 8
	icmp[1] = 0
	icmp[4] = 0x42
	icmp[5] = 0x42
	copy(icmp[8:], icmpPayload)

	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))
	binary.BigEndian.PutUint16(icmp[2:4], icmpChecksum(srcIP, net.IPv4(255, 255, 255, 255), icmp))

	return frame
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
	pseudo[9] = ipProtoICMP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(icmp)))
	copy(pseudo[12:], icmp)
	return ipChecksum(pseudo)
}

func formatMAC(mac []byte) string {
	if len(mac) != 6 {
		return "unknown"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
