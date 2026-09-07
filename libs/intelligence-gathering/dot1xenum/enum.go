package dot1xenum

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"
)

const dot1xTag = "\x1b[38;5;223m[802.1X]\x1b[0m"

var dot1xDst = [6]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}

type rawSocket interface {
	Send(frame []byte) error
	Recv(buf []byte) (int, error)
	Close() error
}

type Enumerator struct {
	Interface string
	SourceMAC string
	EAPInfo   string
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

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Enumeration stopped.\n", dot1xTag)
		os.Exit(0)
	}()

	frame := buildProbeFrame(srcMAC, e.eapIdentity())
	fmt.Printf("%s Sent 802.1X enum frame on %s from %s\n", dot1xTag, iface.Name, srcMAC)
	fmt.Printf("%s Listening for 802.1X packets... (Ctrl+C to stop)\n", dot1xTag)

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
		n, err := sock.Recv(buf)
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		out, ok := formatPacket(buf[:n])
		if !ok {
			continue
		}
		fmt.Printf("%s Recieved 802.1X data from %s:\n%s\n\n", dot1xTag, out.SourceMAC, out.Body)
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

func (e *Enumerator) eapIdentity() string {
	if strings.TrimSpace(e.EAPInfo) == "" {
		return "Cisco Production"
	}
	return e.EAPInfo
}

func buildProbeFrame(srcMAC net.HardwareAddr, identity string) []byte {
	idBytes := []byte(identity)
	eapLen := 4 + 1 + len(idBytes)
	dot1xLen := 4 + eapLen

	frame := make([]byte, 14+dot1xLen)
	copy(frame[0:6], dot1xDst[:])
	copy(frame[6:12], srcMAC)
	frame[12] = 0x88
	frame[13] = 0x8e

	body := frame[14:]
	body[0] = 0x01 // 802.1X-2001
	body[1] = 0x00 // EAP Packet
	body[2] = byte(dot1xLen >> 8)
	body[3] = byte(dot1xLen)

	eap := body[4:]
	eap[0] = 0x02 // EAP Response
	eap[1] = 0x00 // id
	eap[2] = byte(eapLen >> 8)
	eap[3] = byte(eapLen)
	eap[4] = 0x01 // Identity
	copy(eap[5:], idBytes)

	return frame
}
