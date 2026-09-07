// Package arpscan implements active and passive ARP host discovery.
//
// Active mode sends ARP-who-has requests across the specified (or auto-detected)
// subnet and collects ARP replies to enumerate live hosts. Passive mode sniffs
// the wire for any ARP traffic without injecting a single packet.
//
// Both modes use AF_PACKET/SOCK_RAW/ETH_P_ARP — no pcap required.
package arpscan

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"
)

const arpScanTag = "\x1b[38;5;208m[ARP]\x1b[0m" // orange (256-colour)

// arpSocket is satisfied by the platform-specific AF_PACKET implementation.
type arpSocket interface {
	Send(pkt []byte) error
	Recv(buf []byte) (int, error)
	Close() error
}

// Scanner performs ARP-based host discovery.
// Set Passive=true to sniff only; leave it false for active injection.
type Scanner struct {
	Interface string
	Range     string // optional CIDR (e.g. "192.168.1.0/24"); empty = auto-detect
	Passive   bool
}

func (s *Scanner) Run() error {
	iface, err := net.InterfaceByName(s.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", s.Interface, err)
	}
	if s.Passive {
		return s.runPassive(iface)
	}
	return s.runActive(iface)
}

func (s *Scanner) runPassive(iface *net.Interface) error {
	sock, err := openARPSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Passive scan stopped.\n", arpScanTag)
		os.Exit(0)
	}()

	fmt.Printf("%s Passive mode on %s — sniffing ARP traffic. Ctrl+C to stop.\n", arpScanTag, s.Interface)
	fmt.Printf("%s  %-16s  %-17s  Type\n", arpScanTag, "IP", "MAC Address")
	fmt.Printf("%s  %s\n", arpScanTag, "--------------------------------------------")

	seen := make(map[string]bool)
	var mu sync.Mutex
	buf := make([]byte, 65536)

	for {
		n, err := sock.Recv(buf)
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		if n < 42 || !isARP(buf[:n]) {
			continue
		}
		pkt := buf[:n]
		opcode := binary.BigEndian.Uint16(pkt[20:22])
		senderIP := fmtIP(pkt[28:32])
		senderMAC := fmtMAC(pkt[22:28])
		if senderMAC == iface.HardwareAddr.String() {
			continue
		}
		mu.Lock()
		if !seen[senderIP+senderMAC] {
			seen[senderIP+senderMAC] = true
			opStr := "Request"
			if opcode == 2 {
				opStr = "Reply  "
			}
			fmt.Printf("%s  %-16s  %-17s  ARP %s\n", arpScanTag, senderIP, senderMAC, opStr)
		}
		mu.Unlock()
	}
}

func (s *Scanner) runActive(iface *net.Interface) error {
	cidr := s.Range
	if cidr == "" {
		var err error
		cidr, err = ifaceSubnet(iface)
		if err != nil {
			return fmt.Errorf("no IPv4 subnet on %s — use --range <cidr>: %w", s.Interface, err)
		}
	}

	ourIP, ourMAC, err := ifaceIPv4MAC(iface)
	if err != nil {
		return err
	}

	targets, err := cidrHosts(cidr)
	if err != nil {
		return err
	}

	sock, err := openARPSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Active scan stopped.\n", arpScanTag)
		os.Exit(0)
	}()

	seen := make(map[string]bool)
	var mu sync.Mutex

	// Sniffer goroutine: collect ARP replies.
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := sock.Recv(buf)
			if err != nil {
				return // socket closed
			}
			if n < 42 || !isARP(buf[:n]) {
				continue
			}
			pkt := buf[:n]
			if binary.BigEndian.Uint16(pkt[20:22]) != 2 { // only ARP replies
				continue
			}
			senderIP := fmtIP(pkt[28:32])
			senderMAC := fmtMAC(pkt[22:28])
			if senderMAC == iface.HardwareAddr.String() {
				continue
			}
			mu.Lock()
			if !seen[senderIP+senderMAC] {
				seen[senderIP+senderMAC] = true
				fmt.Printf("%s  %-16s  %-17s\n", arpScanTag, senderIP, senderMAC)
			}
			mu.Unlock()
		}
	}()

	fmt.Printf("%s Active scan: %s on %s (%d hosts). Ctrl+C to stop.\n", arpScanTag, cidr, s.Interface, len(targets))
	fmt.Printf("%s  %-16s  %-17s\n", arpScanTag, "IP", "MAC Address")
	fmt.Printf("%s  %s\n", arpScanTag, "--------------------------------------------")

	time.Sleep(100 * time.Millisecond) // let sniffer goroutine start before we inject

	// Inject ARP requests.
	for _, target := range targets {
		_ = sock.Send(buildARPRequest(ourMAC, ourIP, target))
		time.Sleep(time.Millisecond) // 1 ms gap
	}

	// Wait for last replies, trailing sleep(2).
	fmt.Printf("%s All requests sent. Waiting for last replies...\n", arpScanTag)
	time.Sleep(2 * time.Second)
	fmt.Printf("%s Scan finished.\n", arpScanTag)
	return nil
}

// buildARPRequest builds a 42-byte ARP who-has request.
//
//	[0:6]   Ethernet dst  ff:ff:ff:ff:ff:ff (broadcast)
//	[6:12]  Ethernet src  our interface MAC
//	[12:14] EtherType     0x0806
//	[14:16] HW type       0x0001 (Ethernet)
//	[16:18] Proto type    0x0800 (IPv4)
//	[18]    HW addr len   6
//	[19]    Proto addr len 4
//	[20:22] Opcode        0x0001 (request)
//	[22:28] Sender MAC    our interface MAC
//	[28:32] Sender IP     our interface IP
//	[32:38] Target MAC    00:00:00:00:00:00 (unknown)
//	[38:42] Target IP     host to resolve
func buildARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP [4]byte) []byte {
	pkt := make([]byte, 42)
	for i := 0; i < 6; i++ {
		pkt[i] = 0xff // Ethernet dst: broadcast
	}
	copy(pkt[6:12], srcMAC)
	pkt[12] = 0x08; pkt[13] = 0x06 // EtherType ARP
	pkt[14] = 0x00; pkt[15] = 0x01 // HW type: Ethernet
	pkt[16] = 0x08; pkt[17] = 0x00 // Proto type: IPv4
	pkt[18] = 6; pkt[19] = 4       // HW/Proto addr lengths
	pkt[20] = 0x00; pkt[21] = 0x01 // Opcode: request
	copy(pkt[22:28], srcMAC)
	copy(pkt[28:32], srcIP[:])
	// pkt[32:38] left as 00:00:00:00:00:00 (unknown target MAC)
	copy(pkt[38:42], dstIP[:])
	return pkt
}

// cidrHosts enumerates all usable host addresses (excluding network + broadcast)
// in the given CIDR.
func cidrHosts(cidr string) ([][4]byte, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	v4 := ipNet.IP.To4()
	if v4 == nil {
		return nil, fmt.Errorf("only IPv4 CIDR ranges are supported")
	}
	ones, _ := ipNet.Mask.Size()
	if ones > 30 {
		return nil, fmt.Errorf("CIDR prefix /%d is too small to scan (use /30 or wider)", ones)
	}
	network := binary.BigEndian.Uint32(v4)
	total := uint32(1) << uint(32-ones)
	hosts := make([][4]byte, 0, int(total)-2)
	for i := uint32(1); i < total-1; i++ {
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], network+i)
		hosts = append(hosts, a)
	}
	return hosts, nil
}

func ifaceSubnet(iface *net.Interface) (string, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			ones, _ := ipNet.Mask.Size()
			// Mask off host bits to get the network address.
			return fmt.Sprintf("%s/%d", ipNet.IP.Mask(ipNet.Mask), ones), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address")
}

func ifaceIPv4MAC(iface *net.Interface) ([4]byte, net.HardwareAddr, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return [4]byte{}, nil, err
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if v4 := ipNet.IP.To4(); v4 != nil {
				var a [4]byte
				copy(a[:], v4)
				return a, iface.HardwareAddr, nil
			}
		}
	}
	return [4]byte{}, nil, fmt.Errorf("no IPv4 address on %s", iface.Name)
}

func isARP(pkt []byte) bool {
	return len(pkt) >= 14 && pkt[12] == 0x08 && pkt[13] == 0x06
}

func fmtIP(b []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func fmtMAC(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}
