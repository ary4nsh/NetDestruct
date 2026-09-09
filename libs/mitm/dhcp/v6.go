package dhcp

import (
	"encoding/binary"
	"net"
)

// DHCPv6 (RFC 8415) constants. IPv6 has no broadcast and every node already
// has a link-local address, so unlike DHCPv4 there's no "0.0.0.0" client —
// replies just unicast straight back to the client's source address.
const (
	ethTypeIPv6 = 0x86dd

	dhcpv6ClientPort = 546
	dhcpv6ServerPort = 547

	msgSolicit     = 1
	msgAdvertise   = 2
	msgRequestV6   = 3
	msgConfirm     = 4
	msgRenew       = 5
	msgRebind      = 6
	msgReplyV6     = 7
	msgReleaseV6   = 8
	msgDeclineV6   = 9
	msgReconfigure = 10
	msgInfoRequest = 11

	optClientID    = 1
	optServerID6   = 2
	optIANA        = 3
	optIAAddr      = 5
	optDNSServers6 = 23

	duidTypeLL = 3
)

// frameV6 holds a parsed DHCPv6 message.
type frameV6 struct {
	msgType    byte
	xid        uint32 // wire value is 3 bytes
	clientDUID []byte
	iaid       uint32
	reqAddr    net.IP // from a nested IAADDR option, if present
	options    map[uint16][]byte
}

func parseDHCPv6(payload []byte) (*frameV6, bool) {
	if len(payload) < 4 {
		return nil, false
	}
	f := &frameV6{
		msgType: payload[0],
		xid:     uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3]),
		options: map[uint16][]byte{},
	}
	for opts := payload[4:]; len(opts) >= 4; {
		code := binary.BigEndian.Uint16(opts[0:2])
		l := int(binary.BigEndian.Uint16(opts[2:4]))
		if 4+l > len(opts) {
			break
		}
		val := opts[4 : 4+l]
		f.options[code] = append([]byte{}, val...)

		switch code {
		case optClientID:
			f.clientDUID = append([]byte{}, val...)
		case optIANA:
			if len(val) >= 12 {
				f.iaid = binary.BigEndian.Uint32(val[0:4])
				for sub := val[12:]; len(sub) >= 4; {
					scode := binary.BigEndian.Uint16(sub[0:2])
					sl := int(binary.BigEndian.Uint16(sub[2:4]))
					if 4+sl > len(sub) {
						break
					}
					if scode == optIAAddr && sl >= 16 {
						f.reqAddr = append(net.IP{}, sub[4:4+16]...)
					}
					sub = sub[4+sl:]
				}
			}
		}
		opts = opts[4+l:]
	}
	return f, true
}

func encodeOption6(code uint16, val []byte) []byte {
	b := make([]byte, 4+len(val))
	binary.BigEndian.PutUint16(b[0:2], code)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(val)))
	copy(b[4:], val)
	return b
}

// buildServerDUID builds a DUID-LL (RFC 8415 §11.4): the simplest DUID
// variant, just our link-layer (MAC) address tagged with a type.
func buildServerDUID(mac net.HardwareAddr) []byte {
	b := make([]byte, 10)
	binary.BigEndian.PutUint16(b[0:2], duidTypeLL)
	binary.BigEndian.PutUint16(b[2:4], 1) // hardware type: ethernet
	copy(b[4:10], mac)
	return b
}

// dhcpv6Options are the lease parameters offered to a spoofed IPv6 client.
type dhcpv6Options struct {
	serverDUID []byte
	clientDUID []byte // echoed back verbatim, RFC 8415 §18.2
	iaid       uint32
	addr       net.IP
	dns        net.IP
	preferred  uint32
	valid      uint32
}

func (o dhcpv6Options) encode() []byte {
	var b []byte
	b = append(b, encodeOption6(optClientID, o.clientDUID)...)
	b = append(b, encodeOption6(optServerID6, o.serverDUID)...)

	pref, valid := make([]byte, 4), make([]byte, 4)
	binary.BigEndian.PutUint32(pref, o.preferred)
	binary.BigEndian.PutUint32(valid, o.valid)

	iaAddr := append([]byte{}, o.addr.To16()...)
	iaAddr = append(iaAddr, pref...)
	iaAddr = append(iaAddr, valid...)
	iaAddrOpt := encodeOption6(optIAAddr, iaAddr)

	iaidB := make([]byte, 4)
	binary.BigEndian.PutUint32(iaidB, o.iaid)
	iaNA := append([]byte{}, iaidB...)
	iaNA = append(iaNA, 0, 0, 0, 0) // T1 = 0: let the client choose its own renewal time
	iaNA = append(iaNA, 0, 0, 0, 0) // T2 = 0: same, for rebind time
	iaNA = append(iaNA, iaAddrOpt...)
	b = append(b, encodeOption6(optIANA, iaNA)...)

	if o.dns != nil {
		b = append(b, encodeOption6(optDNSServers6, o.dns.To16())...)
	}
	return b
}

func buildDHCPv6Body(msgType byte, xid uint32, opts []byte) []byte {
	b := []byte{msgType, byte(xid >> 16), byte(xid >> 8), byte(xid)}
	return append(b, opts...)
}

// buildIPv6Header builds a minimal 40-byte IPv6 header.
func buildIPv6Header(src, dst net.IP, nextHeader byte, payloadLen int) []byte {
	b := make([]byte, 40)
	b[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(b[4:6], uint16(payloadLen))
	b[6] = nextHeader
	b[7] = 64 // hop limit
	copy(b[8:24], src.To16())
	copy(b[24:40], dst.To16())
	return b
}

// buildUDPv6Header builds an 8-byte UDP header. Unlike IPv4, IPv6 UDP
// checksums are mandatory (RFC 8200 §8.1) — always computed here.
func buildUDPv6Header(src, dst net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], srcPort)
	binary.BigEndian.PutUint16(b[2:4], dstPort)
	udpLen := uint16(8 + len(payload))
	binary.BigEndian.PutUint16(b[4:6], udpLen)

	pseudo := make([]byte, 40)
	copy(pseudo[0:16], src.To16())
	copy(pseudo[16:32], dst.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(udpLen))
	pseudo[39] = 17 // next header: UDP

	cks := checksum(pseudo, b, payload)
	if cks == 0 {
		cks = 0xffff // RFC 768: an all-zero computed checksum is sent as all-ones
	}
	binary.BigEndian.PutUint16(b[6:8], cks)
	return b
}

// buildDHCPv6Frame assembles the full Ethernet+IPv6+UDP+DHCPv6 frame,
// unicast directly to the client's own link-local source address — IPv6
// nodes always have one, so there's no DHCPv4-style "no IP yet" broadcast case.
func buildDHCPv6Frame(dstMAC, srcMAC net.HardwareAddr, srcIP, dstIP net.IP, body []byte) []byte {
	udp := buildUDPv6Header(srcIP, dstIP, dhcpv6ServerPort, dhcpv6ClientPort, body)
	ip6 := buildIPv6Header(srcIP, dstIP, 17, len(udp)+len(body))
	eth := buildEthHeader(dstMAC, srcMAC, ethTypeIPv6)
	frame := append(eth, ip6...)
	frame = append(frame, udp...)
	return append(frame, body...)
}

// parseEthIPv6UDP extracts the UDP payload and addressing info from a raw
// Ethernet frame carrying IPv6. Assumes no IPv6 extension headers between
// the fixed header and UDP, which holds for plain DHCPv6 traffic.
// frame must be a buffer the caller owns exclusively, since payload aliases it.
func parseEthIPv6UDP(frame []byte) (srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte, ok bool) {
	if len(frame) < 14+40+8 {
		return
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethTypeIPv6 {
		return
	}
	dstMAC = append(net.HardwareAddr{}, frame[0:6]...)
	srcMAC = append(net.HardwareAddr{}, frame[6:12]...)

	ip6Start := 14
	if frame[ip6Start+6] != 17 { // next header != UDP
		return
	}
	srcIP = append(net.IP{}, frame[ip6Start+8:ip6Start+24]...)
	dstIP = append(net.IP{}, frame[ip6Start+24:ip6Start+40]...)

	udpStart := ip6Start + 40
	if len(frame) < udpStart+8 {
		return
	}
	srcPort = binary.BigEndian.Uint16(frame[udpStart : udpStart+2])
	dstPort = binary.BigEndian.Uint16(frame[udpStart+2 : udpStart+4])
	udpLen := int(binary.BigEndian.Uint16(frame[udpStart+4 : udpStart+6]))
	if udpLen < 8 || udpStart+udpLen > len(frame) {
		return
	}
	payload = frame[udpStart+8 : udpStart+udpLen]
	ok = true
	return
}
