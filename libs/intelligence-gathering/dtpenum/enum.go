package dtpenum

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"
)

const dtpTag = "\x1b[38;5;208m[DTP]\x1b[0m"

var dtpDst = [6]byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}

type rawSocket interface {
	Send(frame []byte) error
	Recv(buf []byte) (int, error)
	Close() error
}

type Enumerator struct {
	Interface string
	SourceMAC string
}

func (e *Enumerator) Run() error {
	iface, err := net.InterfaceByName(e.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", e.Interface, err)
	}
	src, err := resolveMAC(iface, e.SourceMAC)
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
		fmt.Printf("\n%s Enumeration stopped.\n", dtpTag)
		os.Exit(0)
	}()

	frame := buildProbeFrame(src)
	fmt.Printf("%s Sent DTP enum frame on %s from %s\n", dtpTag, iface.Name, src)
	fmt.Printf("%s Listening for DTP packets... (Ctrl+C to stop)\n", dtpTag)

	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			_ = sock.Send(frame)
		}
	}()

	if err := sock.Send(frame); err != nil {
		return fmt.Errorf("send DTP probe: %w", err)
	}

	buf := make([]byte, 65535)
	for {
		n, err := sock.Recv(buf)
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		pkt, ok := parseDTPFrame(buf[:n])
		if !ok {
			continue
		}
		fmt.Printf("%s Recieved DTP data from %s:\n", dtpTag, pkt.SourceMAC)
		fmt.Println("DTP Data")
		fmt.Printf("%s\n\n", formatDTP(pkt))
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

func buildProbeFrame(src net.HardwareAddr) []byte {
	payload := make([]byte, 0, 64)
	payload = append(payload, 0x01)
	payload = append(payload, tlvString(0x0001, "")...)
	payload = append(payload, tlvByte(0x0002, 0x83)...)
	payload = append(payload, tlvByte(0x0003, 0xa0)...)
	payload = append(payload, tlvSenderID(src)...)
	payload = append(payload, []byte{0x00, 0x00, 0x00, 0x00}...)

	llc := [8]byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x04}
	pLen := len(llc) + len(payload)
	frame := make([]byte, 14+pLen)
	copy(frame[0:6], dtpDst[:])
	copy(frame[6:12], src)
	binary.BigEndian.PutUint16(frame[12:14], uint16(pLen))
	copy(frame[14:22], llc[:])
	copy(frame[22:], payload)
	return frame
}

func tlvString(t uint16, s string) []byte {
	b := make([]byte, 4+len(s))
	binary.BigEndian.PutUint16(b[0:2], t)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[4:], s)
	return b
}

func tlvByte(t uint16, v byte) []byte {
	b := make([]byte, 5)
	binary.BigEndian.PutUint16(b[0:2], t)
	binary.BigEndian.PutUint16(b[2:4], 5)
	b[4] = v
	return b
}

func tlvSenderID(src net.HardwareAddr) []byte {
	b := make([]byte, 10)
	binary.BigEndian.PutUint16(b[0:2], 0x0004)
	binary.BigEndian.PutUint16(b[2:4], 10)
	copy(b[4:10], src)
	return b
}
