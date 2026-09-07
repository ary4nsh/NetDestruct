package dhcpenum

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"
)

const (
	dhcpTag  = "\x1b[35m[DHCP]\x1b[0m"
	dhcp6Tag = "\x1b[35m[DHCP6]\x1b[0m"
)

type rawSocket interface {
	Send(frame []byte) error
	Recv(buf []byte) (int, error)
	Close() error
}

type Enumerator struct {
	Interface string
}

type probeState struct {
	mu      sync.Mutex
	v4XID   uint32
	v6TRID  [3]byte
	seenV4  map[string]struct{}
	seenV6  map[string]struct{}
}

func (e *Enumerator) Run() error {
	iface, err := net.InterfaceByName(e.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", e.Interface, err)
	}
	if len(iface.HardwareAddr) != 6 {
		return fmt.Errorf("interface %s has invalid MAC", iface.Name)
	}
	ethMAC := iface.HardwareAddr
	chaddr := defaultChaddr()

	srcIPv6, v6Err := ifaceIPv6LL(iface)
	v6Enabled := v6Err == nil

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Enumeration stopped.\n", dhcpTag)
		os.Exit(0)
	}()

	state := &probeState{
		seenV4: map[string]struct{}{},
		seenV6: map[string]struct{}{},
	}
	iaid := randIAID()

	sendProbes := func() {
		state.mu.Lock()
		state.v4XID = randXID()
		state.v6TRID = randTRID()
		state.seenV4 = map[string]struct{}{}
		state.seenV6 = map[string]struct{}{}
		v4XID := state.v4XID
		v6TRID := state.v6TRID
		state.mu.Unlock()

		if err := sock.Send(buildDiscoverFrame(ethMAC, chaddr, v4XID)); err != nil {
			fmt.Printf("%s DISCOVER send: %v\n", dhcpTag, err)
		} else {
			fmt.Printf("%s Sent DHCPv4 DISCOVER on %s (xid 0x%08x, chaddr %s)\n",
				dhcpTag, e.Interface, v4XID, chaddr)
		}

		if v6Enabled {
			frame := buildSolicitFrame(ethMAC, srcIPv6, v6TRID, iaid)
			if err := sock.Send(frame); err != nil {
				fmt.Printf("%s SOLICIT send: %v\n", dhcp6Tag, err)
			} else {
				fmt.Printf("%s Sent DHCPv6 SOLICIT on %s (trid 0x%06x, src %s)\n",
					dhcp6Tag, e.Interface, tridToUint(v6TRID), srcIPv6)
			}
		}
	}

	sendProbes()
	fmt.Printf("%s Listening for DHCP OFFER/ACK and DHCPv6 Advertise/Reply... (Ctrl+C to stop)\n", dhcpTag)
	if !v6Enabled {
		fmt.Printf("%s DHCPv6 disabled: %v\n", dhcp6Tag, v6Err)
	}

	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			sendProbes()
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, err := sock.Recv(buf)
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		pkt := buf[:n]

		if msg, ok := parseDHCPv4Frame(pkt); ok {
			state.mu.Lock()
			if msg.xid != state.v4XID {
				state.mu.Unlock()
				continue
			}
			key := fmt.Sprintf("%s:%s:%d", msg.serverIP, msg.yiaddr, msg.msgType)
			if _, dup := state.seenV4[key]; dup {
				state.mu.Unlock()
				continue
			}
			state.seenV4[key] = struct{}{}
			state.mu.Unlock()

			from := msg.serverMAC
			if msg.serverIP != nil && !msg.serverIP.Equal(net.IPv4zero) {
				from = msg.serverIP.String()
			}
			fmt.Printf("%s Recieved DHCPv4 data from %s:\n", dhcpTag, from)
			fmt.Printf("%s\n\n", formatDHCPv4(e.Interface, msg))
			continue
		}

		if msg, ok := parseDHCPv6Frame(pkt); ok {
			state.mu.Lock()
			if msg.trid != state.v6TRID {
				state.mu.Unlock()
				continue
			}
			key := fmt.Sprintf("%s:%d", formatDUID(msg.opts[opt6ServerID]), msg.msgType)
			if _, dup := state.seenV6[key]; dup {
				state.mu.Unlock()
				continue
			}
			state.seenV6[key] = struct{}{}
			state.mu.Unlock()

			from := msg.srcIP.String()
			fmt.Printf("%s Recieved DHCPv6 data from %s:\n", dhcp6Tag, from)
			fmt.Printf("%s\n\n", formatDHCPv6(e.Interface, msg))
		}
	}
}
