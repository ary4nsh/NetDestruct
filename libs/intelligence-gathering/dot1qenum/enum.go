package dot1qenum

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"
)

const (
	dot1qTag = "\x1b[97m[802.1Q]\x1b[0m"
	icmpTag  = "\x1b[34m[ICMP]\x1b[0m"
)

type rawSocket interface {
	Send(frame []byte) error
	Recv(buf []byte) (int, uint16, error)
	Close() error
}

type Enumerator struct {
	Interface string
	SourceMAC string
	Payload   string
}

func (e *Enumerator) Run() error {
	iface, err := net.InterfaceByName(e.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", e.Interface, err)
	}
	srcMAC, err := resolveMAC(iface, e.SourceMAC)
	if err != nil {
		return err
	}
	srcIP, err := ifaceIPv4(iface)
	if err != nil {
		return err
	}

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Enumeration stopped.\n", dot1qTag)
		os.Exit(0)
	}()

	frame := buildProbeFrame(srcMAC, srcIP, e.icmpPayload())
	fmt.Printf("%s Sent 802.1Q enum frame on %s from %s\n", dot1qTag, iface.Name, srcMAC)
	fmt.Printf("%s Listening for 802.1Q packets... (Ctrl+C to stop)\n", dot1qTag)

	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			_ = sock.Send(frame)
		}
	}()

	if err := sock.Send(frame); err != nil {
		return fmt.Errorf("send probe: %w", err)
	}

	buf := make([]byte, 65535)
	for {
		n, strippedVLAN, err := sock.Recv(buf)
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		pkt, ok := formatPacket(buf[:n], strippedVLAN)
		if !ok {
			continue
		}
		if pkt.IsICMP {
			dstMAC := pkt.DstMAC
			if dstMAC == "" {
				dstMAC = "unknown"
			}
			fmt.Printf("%s Recieved 802.1Q ICMP data from %s to %s:\n", icmpTag, pkt.SrcMAC, dstMAC)
		} else {
			fmt.Printf("%s Recieved data from %s:\n", dot1qTag, pkt.SrcMAC)
		}
		fmt.Printf("%s\n\n", pkt.Body)
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

func (e *Enumerator) icmpPayload() string {
	if strings.TrimSpace(e.Payload) == "" {
		return "Cisco Production"
	}
	return e.Payload
}
