package dhcpenum

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	ethTypeIPv4 = 0x0800

	bootRequest = 1
	dhcpMagic   = 0x63825363

	optSubnetMask = 1
	optRouter     = 3
	optDNS        = 6
	optHostName   = 12
	optDomainName = 15
	optLeaseTime  = 51
	optMsgType    = 53
	optServerID   = 54
	optClientID   = 61
	optEnd        = 255

	msgDiscover = 1
	msgOffer    = 2
	msgAck      = 5
	msgNak      = 6

	dhcpClientPort = 68
	dhcpServerPort = 67

	defaultChaddrMAC = "de:ad:c0:de:ca:fe"
)

type dhcpv4Msg struct {
	xid        uint32
	yiaddr     net.IP
	siaddr     net.IP
	msgType    byte
	serverIP   net.IP
	options    map[byte][]byte
	optionList []dhcpOption
	serverMAC  string
}

func defaultChaddr() net.HardwareAddr {
	m, _ := net.ParseMAC(defaultChaddrMAC)
	return m
}

func buildDiscoverFrame(ethMAC, chaddr net.HardwareAddr, xid uint32) []byte {
	opts := []byte{0x35, 0x01, msgDiscover, optEnd}

	dhcp := make([]byte, 240+len(opts))
	dhcp[0] = bootRequest
	dhcp[1] = 1
	dhcp[2] = 6
	binary.BigEndian.PutUint32(dhcp[4:8], xid)
	binary.BigEndian.PutUint16(dhcp[10:12], 0x8000)
	copy(dhcp[28:34], chaddr[:])
	binary.BigEndian.PutUint32(dhcp[236:240], dhcpMagic)
	copy(dhcp[240:], opts)

	udpLen := 8 + len(dhcp)
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], dhcpClientPort)
	binary.BigEndian.PutUint16(udp[2:4], dhcpServerPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], dhcp)
	srcIP := net.IPv4zero.To4()
	dstIP := net.IPv4bcast.To4()
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(srcIP, dstIP, udp))

	ipTotalLen := 20 + udpLen
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(ipTotalLen))
	ipHdr[8] = 64
	ipHdr[9] = 17
	copy(ipHdr[12:16], srcIP)
	copy(ipHdr[16:20], dstIP)
	binary.BigEndian.PutUint16(ipHdr[10:12], ipChecksum(ipHdr))

	frame := make([]byte, 14+ipTotalLen)
	for i := 0; i < 6; i++ {
		frame[i] = 0xff
	}
	copy(frame[6:12], ethMAC)
	binary.BigEndian.PutUint16(frame[12:14], ethTypeIPv4)
	copy(frame[14:34], ipHdr)
	copy(frame[34:], udp)
	return frame
}

func parseDHCPv4Frame(frame []byte) (*dhcpv4Msg, bool) {
	if len(frame) < 14+20+8+240 {
		return nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethTypeIPv4 {
		return nil, false
	}
	ipStart := 14
	ihl := int(frame[ipStart]&0x0f) * 4
	if ihl < 20 || len(frame) < ipStart+ihl+8 {
		return nil, false
	}
	if frame[ipStart+9] != 17 {
		return nil, false
	}
	udpStart := ipStart + ihl
	srcPort := binary.BigEndian.Uint16(frame[udpStart : udpStart+2])
	dstPort := binary.BigEndian.Uint16(frame[udpStart+2 : udpStart+4])
	if dstPort != dhcpClientPort || srcPort != dhcpServerPort {
		return nil, false
	}
	udpLen := int(binary.BigEndian.Uint16(frame[udpStart+4 : udpStart+6]))
	if udpLen < 8 || udpStart+udpLen > len(frame) {
		return nil, false
	}
	payload := frame[udpStart+8 : udpStart+udpLen]
	if len(payload) < 240 {
		return nil, false
	}
	if binary.BigEndian.Uint32(payload[236:240]) != dhcpMagic {
		return nil, false
	}
	if payload[0] != 2 {
		return nil, false
	}

	m := &dhcpv4Msg{
		xid:        binary.BigEndian.Uint32(payload[4:8]),
		yiaddr:     net.IP(append([]byte{}, payload[16:20]...)),
		siaddr:     net.IP(append([]byte{}, payload[20:24]...)),
		options:    map[byte][]byte{},
		optionList: make([]dhcpOption, 0, 8),
	}
	if len(frame) >= 12 {
		m.serverMAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			frame[6], frame[7], frame[8], frame[9], frame[10], frame[11])
	}
	for opts := payload[240:]; len(opts) > 0; {
		code := opts[0]
		if code == optEnd {
			break
		}
		if code == 0 {
			opts = opts[1:]
			continue
		}
		if len(opts) < 2 {
			break
		}
		l := int(opts[1])
		if 2+l > len(opts) {
			break
		}
		m.options[code] = append([]byte{}, opts[2:2+l]...)
		m.optionList = append(m.optionList, dhcpOption{Code: code, Data: append([]byte{}, opts[2:2+l]...)})
		opts = opts[2+l:]
	}
	if mt, ok := m.options[optMsgType]; ok && len(mt) == 1 {
		m.msgType = mt[0]
	}
	if mt := m.msgType; mt != msgOffer && mt != msgAck && mt != msgNak {
		return nil, false
	}
	if sid, ok := m.options[optServerID]; ok && len(sid) == 4 {
		m.serverIP = net.IP(sid)
	} else if m.siaddr != nil && !m.siaddr.Equal(net.IPv4zero) {
		m.serverIP = m.siaddr
	}
	return m, true
}

func randXID() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:]) & 0x7fffffff
}

func randTRID() [3]byte {
	var t [3]byte
	rand.Read(t[:])
	return t
}

func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	if len(hdr)%2 == 1 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpChecksum(srcIP, dstIP net.IP, udp []byte) uint16 {
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	return ipChecksum(pseudo)
}
