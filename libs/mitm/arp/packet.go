package arp

import (
	"encoding/binary"
	"net"
)

// Ethernet (RFC 894) and protocol constants used to build/parse raw frames.
const (
	ethTypeARP  = 0x0806
	ethTypeIPv6 = 0x86dd

	arpHwEthernet = 1
	arpProtoIPv4  = 0x0800
	arpOpRequest  = 1
	arpOpReply    = 2

	icmpv6NeighborSolicitation  = 135
	icmpv6NeighborAdvertisement = 136
	ndpOptSourceLinkAddr        = 1
	ndpOptTargetLinkAddr        = 2

	ndpFlagSolicited = 0x40000000
	ndpFlagOverride  = 0x20000000
)

var (
	broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	zeroMAC      = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

// buildEthHeader builds a 14-byte Ethernet II header.
func buildEthHeader(dst, src net.HardwareAddr, ethType uint16) []byte {
	b := make([]byte, 14)
	copy(b[0:6], dst)
	copy(b[6:12], src)
	binary.BigEndian.PutUint16(b[12:14], ethType)
	return b
}

// buildARPFrame builds a complete Ethernet+ARP frame (RFC 826).
func buildARPFrame(op uint16, ethDst, senderMAC net.HardwareAddr, senderIP net.IP, arpTargetMAC net.HardwareAddr, targetIP net.IP) []byte {
	frame := buildEthHeader(ethDst, senderMAC, ethTypeARP)
	arp := make([]byte, 28)
	binary.BigEndian.PutUint16(arp[0:2], arpHwEthernet)
	binary.BigEndian.PutUint16(arp[2:4], arpProtoIPv4)
	arp[4] = 6 // hardware address length
	arp[5] = 4 // protocol address length
	binary.BigEndian.PutUint16(arp[6:8], op)
	copy(arp[8:14], senderMAC)
	copy(arp[14:18], senderIP.To4())
	copy(arp[18:24], arpTargetMAC)
	copy(arp[24:28], targetIP.To4())
	return append(frame, arp...)
}

// arpInfo holds a parsed ARP packet's fields.
type arpInfo struct {
	op        uint16
	senderMAC net.HardwareAddr
	senderIP  net.IP
	targetIP  net.IP
}

// parseARP parses a raw Ethernet frame as ARP-over-Ethernet/IPv4.
// Returns ok=false for anything that isn't a well-formed ARP/Ethernet/IPv4 packet.
func parseARP(frame []byte) (*arpInfo, bool) {
	if len(frame) < 14+28 {
		return nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethTypeARP {
		return nil, false
	}
	p := frame[14:42]
	if binary.BigEndian.Uint16(p[0:2]) != arpHwEthernet || binary.BigEndian.Uint16(p[2:4]) != arpProtoIPv4 {
		return nil, false
	}
	return &arpInfo{
		op:        binary.BigEndian.Uint16(p[6:8]),
		senderMAC: append(net.HardwareAddr{}, p[8:14]...),
		senderIP:  append(net.IP{}, p[14:18]...),
		targetIP:  append(net.IP{}, p[24:28]...),
	}, true
}

// checksum computes the standard one's-complement Internet checksum
// (RFC 1071) over the concatenation of all supplied buffers in a single pass.
func checksum(buffers ...[]byte) uint16 {
	var sum uint32
	for _, buf := range buffers {
		n := len(buf)
		for i := 0; i+1 < n; i += 2 {
			sum += uint32(buf[i])<<8 | uint32(buf[i+1])
		}
		if n%2 == 1 {
			sum += uint32(buf[n-1]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildIPv6Header builds a minimal 40-byte IPv6 header.
// Hop Limit is fixed at 255, as required for NDP packets to be accepted
// by a standards-compliant stack (RFC 4861 §7.1.1/§7.1.2).
func buildIPv6Header(src, dst net.IP, nextHeader byte, payloadLen int) []byte {
	b := make([]byte, 40)
	b[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(b[4:6], uint16(payloadLen))
	b[6] = nextHeader
	b[7] = 255
	copy(b[8:24], src.To16())
	copy(b[24:40], dst.To16())
	return b
}

// icmpv6Checksum computes the ICMPv6 checksum over the IPv6 pseudo-header
// (RFC 8200 §8.1) plus the ICMPv6 message. icmp's checksum field must be
// zero when calling this.
func icmpv6Checksum(src, dst net.IP, icmp []byte) uint16 {
	pseudo := make([]byte, 40)
	copy(pseudo[0:16], src.To16())
	copy(pseudo[16:32], dst.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(icmp)))
	pseudo[39] = 58 // Next Header = ICMPv6
	return checksum(pseudo, icmp)
}

// solicitedNodeMulticast derives the IPv6 solicited-node multicast address
// for target (RFC 4291 §2.7.1): ff02::1:ffXX:XXXX using target's low 24 bits.
func solicitedNodeMulticast(target net.IP) net.IP {
	t := target.To16()
	return net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, t[13], t[14], t[15]}
}

// multicastEthMAC derives the Ethernet multicast MAC for an IPv6 multicast
// address (RFC 2464 §7): 33:33 followed by the low 32 bits of the address.
func multicastEthMAC(ip net.IP) net.HardwareAddr {
	b := ip.To16()
	return net.HardwareAddr{0x33, 0x33, b[12], b[13], b[14], b[15]}
}

// buildNS builds an Ethernet+IPv6+ICMPv6 Neighbor Solicitation frame
// (RFC 4861 §4.3) asking who owns targetIP, sent to its solicited-node
// multicast group.
func buildNS(srcMAC net.HardwareAddr, srcIP, targetIP net.IP) []byte {
	dstIP := solicitedNodeMulticast(targetIP)

	icmp := make([]byte, 24)
	icmp[0] = icmpv6NeighborSolicitation
	copy(icmp[8:24], targetIP.To16())
	icmp = append(icmp, ndpOption(ndpOptSourceLinkAddr, srcMAC)...)
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(srcIP, dstIP, icmp))

	ip6 := buildIPv6Header(srcIP, dstIP, 58, len(icmp))
	eth := buildEthHeader(multicastEthMAC(dstIP), srcMAC, ethTypeIPv6)

	frame := append(eth, ip6...)
	return append(frame, icmp...)
}

// buildGratuitousNA builds an unsolicited Neighbor Advertisement (RFC 4861
// §4.4, §7.2.5) impersonating claimedIP: the IPv6 source address is set to
// claimedIP itself (the spoofed identity) and the Target Link-Layer Address
// option is set to attackerMAC, exactly mirroring a gratuitous ARP reply.
// Sent to the all-nodes multicast group so every host on the link updates
// its neighbor cache.
func buildGratuitousNA(attackerMAC net.HardwareAddr, claimedIP net.IP) []byte {
	dstIP := net.ParseIP("ff02::1")
	dstMAC := net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}

	icmp := make([]byte, 24)
	icmp[0] = icmpv6NeighborAdvertisement
	binary.BigEndian.PutUint32(icmp[4:8], ndpFlagOverride)
	copy(icmp[8:24], claimedIP.To16())
	icmp = append(icmp, ndpOption(ndpOptTargetLinkAddr, attackerMAC)...)
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(claimedIP, dstIP, icmp))

	ip6 := buildIPv6Header(claimedIP, dstIP, 58, len(icmp))
	eth := buildEthHeader(dstMAC, attackerMAC, ethTypeIPv6)

	frame := append(eth, ip6...)
	return append(frame, icmp...)
}

// ndpOption builds an 8-byte NDP link-layer-address option.
func ndpOption(optType byte, mac net.HardwareAddr) []byte {
	return []byte{optType, 1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]}
}

// ndpInfo holds a parsed NDP (Neighbor Solicitation/Advertisement) packet.
type ndpInfo struct {
	icmpType byte
	target   net.IP
	linkAddr net.HardwareAddr // from the NDP option, if present
	ethSrc   net.HardwareAddr // source MAC from the Ethernet header
}

// parseNDP parses a raw Ethernet frame as IPv6/ICMPv6 NS or NA.
func parseNDP(frame []byte) (*ndpInfo, bool) {
	const ethLen, ip6Len, icmpMinLen = 14, 40, 24
	if len(frame) < ethLen+ip6Len+icmpMinLen {
		return nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethTypeIPv6 {
		return nil, false
	}
	ip6 := frame[ethLen : ethLen+ip6Len]
	if ip6[6] != 58 { // Next Header = ICMPv6
		return nil, false
	}
	icmp := frame[ethLen+ip6Len:]
	t := icmp[0]
	if t != icmpv6NeighborSolicitation && t != icmpv6NeighborAdvertisement {
		return nil, false
	}

	info := &ndpInfo{
		icmpType: t,
		target:   append(net.IP{}, icmp[8:24]...),
		ethSrc:   append(net.HardwareAddr{}, frame[6:12]...),
	}

	for opts := icmp[24:]; len(opts) >= 8; {
		optLen := int(opts[1]) * 8
		if optLen == 0 || optLen > len(opts) {
			break
		}
		if opts[0] == ndpOptSourceLinkAddr || opts[0] == ndpOptTargetLinkAddr {
			info.linkAddr = append(net.HardwareAddr{}, opts[2:8]...)
		}
		opts = opts[optLen:]
	}
	return info, true
}
