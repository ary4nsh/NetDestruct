package dhcpenum

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	ethTypeIPv6 = 0x86DD

	dhcp6ClientPort = 546
	dhcp6ServerPort = 547

	dhcp6Solicit  = 1
	dhcp6Advert   = 2
	dhcp6Reply    = 7

	opt6ClientID  = 1
	opt6ServerID  = 2
	opt6IANA      = 3
	opt6IAAddr    = 5
	opt6DNS       = 23
	opt6DomainSrch = 24
	opt6SNTP       = 31
)

var (
	dhcp6MulticastMAC = net.HardwareAddr{0x33, 0x33, 0x00, 0x01, 0x00, 0x02}
	dhcp6MulticastIP  = net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02}
)

type dhcpv6Msg struct {
	trid       [3]byte
	msgType    byte
	srcIP      net.IP
	serverMAC  string
	opts       map[uint16][]byte
	optionList []dhcpv6Option
}

func buildDUIDLL(mac net.HardwareAddr) []byte {
	d := make([]byte, 10)
	binary.BigEndian.PutUint16(d[0:2], 3)
	binary.BigEndian.PutUint16(d[2:4], 1)
	copy(d[4:], mac)
	return d
}

func buildSolicitFrame(ethMAC net.HardwareAddr, srcIP net.IP, trid [3]byte, iaid [4]byte) []byte {
	clientDUID := buildDUIDLL(ethMAC)
	iana := make([]byte, 16)
	binary.BigEndian.PutUint16(iana[0:2], opt6IANA)
	binary.BigEndian.PutUint16(iana[2:4], 12)
	copy(iana[4:8], iaid[:])

	var payload bytes.Buffer
	payload.WriteByte(dhcp6Solicit)
	payload.Write(trid[:])
	writeOpt6(&payload, opt6ClientID, clientDUID)
	payload.Write(iana)
	writeOpt6(&payload, 6, []byte{23, 24, 31}) // ORO: DNS, domain search, SNTP

	udpLen := 8 + payload.Len()
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], dhcp6ClientPort)
	binary.BigEndian.PutUint16(udp[2:4], dhcp6ServerPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload.Bytes())
	cksum := ipv6L4Checksum(srcIP.To16(), dhcp6MulticastIP, 17, udp)
	binary.BigEndian.PutUint16(udp[6:8], cksum)
	return buildIPv6Frame(ethMAC, dhcp6MulticastMAC, srcIP, dhcp6MulticastIP, 17, 64, udp)
}

func writeOpt6(w *bytes.Buffer, code uint16, data []byte) {
	var h [4]byte
	binary.BigEndian.PutUint16(h[0:2], code)
	binary.BigEndian.PutUint16(h[2:4], uint16(len(data)))
	w.Write(h[:])
	w.Write(data)
}

func buildIPv6Frame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, nextHdr, hopLimit byte, payload []byte) []byte {
	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(len(payload)))
	ipv6[6] = nextHdr
	ipv6[7] = hopLimit
	copy(ipv6[8:24], srcIP.To16())
	copy(ipv6[24:40], dstIP.To16())

	frame := make([]byte, 14+40+len(payload))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], ethTypeIPv6)
	copy(frame[14:54], ipv6)
	copy(frame[54:], payload)
	return frame
}

func ipv6L4Checksum(srcIP, dstIP net.IP, nextHdr byte, payload []byte) uint16 {
	pseudo := make([]byte, 40+len(payload))
	copy(pseudo[0:16], srcIP.To16())
	copy(pseudo[16:32], dstIP.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(payload)))
	pseudo[39] = nextHdr
	copy(pseudo[40:], payload)
	return ipChecksum(pseudo)
}

func parseDHCPv6Frame(frame []byte) (*dhcpv6Msg, bool) {
	if len(frame) < 14+40+8+4 {
		return nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethTypeIPv6 {
		return nil, false
	}
	if frame[20] != 17 {
		return nil, false
	}
	srcPort := binary.BigEndian.Uint16(frame[54:56])
	dstPort := binary.BigEndian.Uint16(frame[56:58])
	if dstPort != dhcp6ClientPort || srcPort != dhcp6ServerPort {
		return nil, false
	}
	udpLen := int(binary.BigEndian.Uint16(frame[58:60]))
	if udpLen < 8 || 54+udpLen > len(frame) {
		return nil, false
	}
	data := frame[62 : 54+udpLen]
	if len(data) < 4 {
		return nil, false
	}
	msgType := data[0]
	if msgType != dhcp6Advert && msgType != dhcp6Reply {
		return nil, false
	}
	m := &dhcpv6Msg{
		msgType:    msgType,
		srcIP:      net.IP(append([]byte{}, frame[22:38]...)),
		opts:       map[uint16][]byte{},
		optionList: make([]dhcpv6Option, 0, 8),
	}
	copy(m.trid[:], data[1:4])
	if len(frame) >= 12 {
		m.serverMAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			frame[6], frame[7], frame[8], frame[9], frame[10], frame[11])
	}
	for i := 4; i+4 <= len(data); {
		code := binary.BigEndian.Uint16(data[i : i+2])
		l := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		i += 4
		if i+l > len(data) {
			break
		}
		m.opts[code] = append([]byte{}, data[i:i+l]...)
		m.optionList = append(m.optionList, dhcpv6Option{Code: code, Data: append([]byte{}, data[i:i+l]...)})
		i += l
	}
	return m, true
}

func ifaceIPv6LL(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ip := ipNet.IP; ip.To4() == nil && ip.IsLinkLocalUnicast() {
				return ip, nil
			}
		}
	}
	if len(iface.HardwareAddr) == 6 {
		return macToLinkLocal(iface.HardwareAddr), nil
	}
	return nil, fmt.Errorf("no IPv6 link-local on %s", iface.Name)
}

func macToLinkLocal(mac net.HardwareAddr) net.IP {
	ip := make(net.IP, 16)
	ip[0] = 0xfe
	ip[1] = 0x80
	ip[8] = mac[0] ^ 0x02
	ip[9] = mac[1]
	ip[10] = mac[2]
	ip[11] = 0xff
	ip[12] = 0xfe
	ip[13] = mac[3]
	ip[14] = mac[4]
	ip[15] = mac[5]
	return ip
}

func randIAID() [4]byte {
	var iaid [4]byte
	rand.Read(iaid[:])
	return iaid
}
