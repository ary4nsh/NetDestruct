package dhcp

import (
	"encoding/binary"
	"net"
)

// DHCPv4 (RFC 2131) constants.
const (
	ethTypeIPv4 = 0x0800

	bootRequest = 1
	bootReply   = 2

	dhcpMagicCookie = 0x63825363
	dhcpHdrLen      = 240   // fixed BOOTP header, before options
	dhcpOptMinLen   = 0x12c // 300: legacy BOOTP minimum options length some
	// clients (Windows included) still enforce — too-short replies get
	// silently discarded as malformed.

	optSubnetMask  = 1
	optRouter      = 3
	optDNS         = 6
	optDomainName  = 15
	optRequestedIP = 50
	optLeaseTime   = 51
	optMsgType     = 53
	optServerID    = 54
	optRenewTime   = 58
	optEnd         = 255

	msgDiscover = 1
	msgOffer    = 2
	msgRequest  = 3
	msgDecline  = 4
	msgAck      = 5
	msgNak      = 6
	msgRelease  = 7
	msgInform   = 8

	dhcpClientPort = 68
	dhcpServerPort = 67
)

// frameV4 holds a parsed DHCPv4 message (BOOTP header + decoded options).
// raw retains the original 240-byte header verbatim — see replyHeader.
type frameV4 struct {
	raw     []byte
	op      byte
	ciaddr  net.IP
	yiaddr  net.IP
	chaddr  net.HardwareAddr
	msgType byte
	options map[byte][]byte
}

// parseDHCPv4 parses a UDP payload as a DHCPv4/BOOTP message.
func parseDHCPv4(payload []byte) (*frameV4, bool) {
	if len(payload) < dhcpHdrLen {
		return nil, false
	}
	if binary.BigEndian.Uint32(payload[236:240]) != dhcpMagicCookie {
		return nil, false
	}
	f := &frameV4{
		raw:     append([]byte{}, payload[:dhcpHdrLen]...),
		op:      payload[0],
		ciaddr:  append(net.IP{}, payload[12:16]...),
		yiaddr:  append(net.IP{}, payload[16:20]...),
		chaddr:  append(net.HardwareAddr{}, payload[28:34]...),
		options: map[byte][]byte{},
	}
	for opts := payload[dhcpHdrLen:]; len(opts) > 0; {
		t := opts[0]
		if t == optEnd {
			break
		}
		if t == 0 { // pad
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
		f.options[t] = append([]byte{}, opts[2:2+l]...)
		opts = opts[2+l:]
	}
	if mt, ok := f.options[optMsgType]; ok && len(mt) == 1 {
		f.msgType = mt[0]
	}
	return f, true
}

// requestedIP returns the IP a REQUEST/DECLINE/RELEASE message refers to:
// the explicit "requested IP" option if present, else ciaddr.
func (f *frameV4) requestedIP() net.IP {
	if ip, ok := f.options[optRequestedIP]; ok && len(ip) == 4 {
		return net.IP(ip)
	}
	if !f.ciaddr.Equal(net.IPv4zero) {
		return f.ciaddr
	}
	return nil
}

// replyHeader builds a reply's 240-byte BOOTP header by copying the
// client's original request header verbatim and patching only the fields
// a server is responsible for: op, yiaddr, siaddr. secs, flags, hops,
// ciaddr, giaddr, chaddr (all 16 bytes), sname and file all stay exactly
// as the client sent them.
//
// A from-scratch, mostly-zeroed header (the previous approach here) gets
// silently discarded by Windows' DHCP client — it never progresses past
// DISCOVER no matter how many OFFERs are sent.
func (f *frameV4) replyHeader(yiaddr, siaddr net.IP) []byte {
	b := append([]byte{}, f.raw...)
	b[0] = bootReply
	copy(b[16:20], yiaddr.To4())
	copy(b[20:24], siaddr.To4())
	return b
}

// dhcpv4Options are the lease parameters offered to a spoofed client.
type dhcpv4Options struct {
	serverID net.IP
	mask     net.IP
	router   net.IP
	dns      net.IP
	domain   string
	leaseSec uint32
	renewSec uint32
}

// buildOptions encodes the option list for a fake OFFER/ACK.
func (o dhcpv4Options) encode(msgType byte) []byte {
	b := make([]byte, 0, dhcpOptMinLen)
	put := func(code byte, val []byte) {
		b = append(b, code, byte(len(val)))
		b = append(b, val...)
	}
	put(optMsgType, []byte{msgType})
	put(optServerID, o.serverID.To4())
	lease := make([]byte, 4)
	binary.BigEndian.PutUint32(lease, o.leaseSec)
	put(optLeaseTime, lease)
	if o.renewSec > 0 {
		renew := make([]byte, 4)
		binary.BigEndian.PutUint32(renew, o.renewSec)
		put(optRenewTime, renew)
	}
	if o.mask != nil {
		put(optSubnetMask, o.mask.To4())
	}
	if o.router != nil {
		put(optRouter, o.router.To4())
	}
	if o.dns != nil {
		put(optDNS, o.dns.To4())
	}
	if o.domain != "" {
		put(optDomainName, []byte(o.domain))
	}
	b = append(b, optEnd)
	// Zero-pad past the END marker up to the legacy BOOTP minimum: a real
	// option list can be much shorter, but plenty of DHCP client stacks
	// (Windows included) silently drop replies shorter than this.
	if len(b) < dhcpOptMinLen {
		b = append(b, make([]byte, dhcpOptMinLen-len(b))...)
	}
	return b
}

// buildIPv4Header builds a minimal 20-byte IPv4 header (no options).
// l4Len is the length of everything after the IP header (UDP header +
// payload), so the Total Length field is simply 20 + l4Len. Getting this
// wrong — e.g. double-counting the UDP header — makes the datagram claim to
// be longer than the frame actually is, and Windows silently drops it as
// truncated, so the client never accepts the lease.
func buildIPv4Header(src, dst net.IP, l4Len int) []byte {
	b := make([]byte, 20)
	b[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(b[2:4], uint16(20+l4Len))
	b[8] = 64 // TTL
	b[9] = 17 // protocol: UDP
	copy(b[12:16], src.To4())
	copy(b[16:20], dst.To4())
	binary.BigEndian.PutUint16(b[10:12], checksum(b))
	return b
}

// buildUDPHeader builds an 8-byte UDP header with the IPv4 pseudo-header
// checksum (RFC 768) covering header+payload.
func buildUDPHeader(src, dst net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], srcPort)
	binary.BigEndian.PutUint16(b[2:4], dstPort)
	udpLen := uint16(8 + len(payload))
	binary.BigEndian.PutUint16(b[4:6], udpLen)

	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[9] = 17 // UDP
	binary.BigEndian.PutUint16(pseudo[10:12], udpLen)

	cks := checksum(pseudo, b, payload)
	if cks == 0 {
		cks = 0xffff // RFC 768: a computed checksum of 0 is transmitted as all-ones
	}
	binary.BigEndian.PutUint16(b[6:8], cks)
	return b
}

// buildDHCPv4Frame assembles the full Ethernet+IPv4+UDP+DHCP frame.
// Unicast at the Ethernet layer directly
// to the requesting client's MAC (bypassing ARP, which a brand-new client
// can't yet answer), while the IP layer destination follows
// replyDestIPv4 (broadcast if the client has no IP yet, else its own IP).
func buildDHCPv4Frame(dstMAC, srcMAC net.HardwareAddr, srcIP, dstIP net.IP, dhcpBody []byte) []byte {
	udp := buildUDPHeader(srcIP, dstIP, dhcpServerPort, dhcpClientPort, dhcpBody)
	ip := buildIPv4Header(srcIP, dstIP, len(udp)+len(dhcpBody))
	eth := buildEthHeader(dstMAC, srcMAC, ethTypeIPv4)
	frame := append(eth, ip...)
	frame = append(frame, udp...)
	return append(frame, dhcpBody...)
}

// replyDestIPv4: a client with no IP yet
// sources its request from 0.0.0.0, so the reply must go to the broadcast
// address; a renewing client with an existing ciaddr gets a direct unicast.
func replyDestIPv4(reqSrcIP net.IP) net.IP {
	if reqSrcIP == nil || reqSrcIP.Equal(net.IPv4zero) {
		return net.IPv4bcast
	}
	return reqSrcIP
}

// parseEthIPv4UDP extracts the UDP payload and addressing info from a raw
// Ethernet frame. frame must be a buffer the caller owns exclusively (e.g.
// already copied out of a shared read buffer) since payload aliases it.
func parseEthIPv4UDP(frame []byte) (srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte, ok bool) {
	if len(frame) < 14+20+8 {
		return
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethTypeIPv4 {
		return
	}
	dstMAC = append(net.HardwareAddr{}, frame[0:6]...)
	srcMAC = append(net.HardwareAddr{}, frame[6:12]...)

	ipStart := 14
	ihl := int(frame[ipStart]&0x0f) * 4
	if ihl < 20 || len(frame) < ipStart+ihl+8 {
		return
	}
	if frame[ipStart+9] != 17 { // protocol != UDP
		return
	}
	srcIP = append(net.IP{}, frame[ipStart+12:ipStart+16]...)
	dstIP = append(net.IP{}, frame[ipStart+16:ipStart+20]...)

	udpStart := ipStart + ihl
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
