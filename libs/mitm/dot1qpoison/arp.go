package dot1qpoison

import (
	"encoding/binary"
	"net"
)

func parseARPReplyForIP(frame []byte, wantIP net.IP, ourMAC net.HardwareAddr) (net.HardwareAddr, bool) {
	if len(frame) < 42 {
		return nil, false
	}
	if macEqual(frame[6:12], ourMAC) {
		return nil, false
	}

	off := 12
	for off+4 <= len(frame) {
		et := binary.BigEndian.Uint16(frame[off : off+2])
		if et != 0x8100 && et != 0x88a8 {
			break
		}
		off += 4
	}
	if off+2 > len(frame) || binary.BigEndian.Uint16(frame[off:off+2]) != ethTypeARP {
		return nil, false
	}
	arpOff := off + 2
	if arpOff+28 > len(frame) {
		return nil, false
	}
	if binary.BigEndian.Uint16(frame[arpOff+6:arpOff+8]) != arpOpReply {
		return nil, false
	}
	replyIP := net.IP(frame[arpOff+14 : arpOff+18])
	if !replyIP.Equal(wantIP) {
		return nil, false
	}
	return append(net.HardwareAddr{}, frame[6:12]...), true
}

func isFromTarget(frame []byte, targetIP net.IP, victimMAC, ourMAC net.HardwareAddr) bool {
	if len(frame) < 14 || macEqual(frame[6:12], ourMAC) {
		return false
	}
	if len(victimMAC) == 6 && macEqual(frame[6:12], victimMAC) {
		return true
	}
	if ip := frameSourceIP(frame); ip != nil && ip.Equal(targetIP) {
		return true
	}
	return false
}

func frameSourceIP(frame []byte) net.IP {
	off := 12
	for off+4 <= len(frame) {
		et := binary.BigEndian.Uint16(frame[off : off+2])
		if et == ethTypeVLAN || et == 0x88a8 {
			off += 4
			continue
		}
		if et == ethTypeIPv4 {
			ipOff := off + 2
			if ipOff+20 <= len(frame) && frame[ipOff]>>4 == 4 {
				return net.IP(append([]byte{}, frame[ipOff+12:ipOff+16]...))
			}
			return nil
		}
		if et == ethTypeARP {
			arpOff := off + 2
			if arpOff+18 <= len(frame) {
				return net.IP(append([]byte{}, frame[arpOff+14:arpOff+18]...))
			}
			return nil
		}
		return nil
	}
	return nil
}

func buildTaggedICMP(srcMAC net.HardwareAddr, srcIP net.IP, vlan int, payload string) []byte {
	const priority = 7
	tci := uint16(priority<<13 | (uint16(vlan) & 0xfff))

	icmpPayload := []byte(payload)
	icmpLen := 8 + len(icmpPayload)
	ipLen := 20 + icmpLen
	total := 14 + 4 + ipLen

	frame := make([]byte, total)
	copy(frame[0:6], broadcastMAC[:])
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], ethTypeVLAN)
	binary.BigEndian.PutUint16(frame[14:16], tci)
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)

	ip := frame[18:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	ip[8] = 64
	ip[9] = 1
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
	pseudo[9] = 1
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(icmp)))
	copy(pseudo[12:], icmp)
	return ipChecksum(pseudo)
}
