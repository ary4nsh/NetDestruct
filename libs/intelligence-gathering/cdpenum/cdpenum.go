package cdpenum

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
	cdpTag = "\x1b[34m[CDP]\x1b[0m"

	cdpDstMAC = "\x01\x00\x0c\xcc\xcc\xcc"
	cdpVer    = 2
	cdpTTL    = 180
)

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
	srcMAC, err := sourceMAC(iface, e.SourceMAC)
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
		fmt.Printf("\n%s Enumeration stopped.\n", cdpTag)
		os.Exit(0)
	}()

	probe := buildProbeFrame(srcMAC)
	if err := sock.Send(probe); err != nil {
		return fmt.Errorf("send CDP probe: %w", err)
	}
	fmt.Printf("%s Sent CDP enum frame on %s from %s\n", cdpTag, e.Interface, srcMAC)
	fmt.Printf("%s Listening for CDP packets... (Ctrl+C to stop)\n", cdpTag)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			_ = sock.Send(probe)
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, err := sock.Recv(buf)
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		pkt, ok := parseCDPFrame(buf[:n])
		if !ok {
			continue
		}
		fmt.Printf("%s Recieved CDP data from %s:\n", cdpTag, pkt.SourceMAC)
		fmt.Printf("%s\n\n", formatCDP(pkt))
	}
}

func sourceMAC(iface *net.Interface, override string) (net.HardwareAddr, error) {
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

func buildProbeFrame(srcMAC net.HardwareAddr) []byte {
	devID := []byte("NetDestruct")
	port := []byte("GigabitEthernet0/1")
	platform := []byte("Cisco")
	sw := []byte("Cisco IOS Software")

	tlvs := make([]byte, 0, 128)
	tlvs = append(tlvs, tlvString(0x0001, devID)...)
	tlvs = append(tlvs, tlvAddressesZero()...)
	tlvs = append(tlvs, tlvString(0x0003, port)...)
	tlvs = append(tlvs, tlvU32(0x0004, 0x00000029)...)
	tlvs = append(tlvs, tlvString(0x0005, sw)...)
	tlvs = append(tlvs, tlvString(0x0006, platform)...)
	tlvs = append(tlvs, tlvU16(0x000a, 1)...)
	tlvs = append(tlvs, tlvByte(0x000b, 1)...)
	tlvs = append(tlvs, []byte{0x00, 0x00, 0x00, 0x00}...) // End TLV

	cdp := make([]byte, 4+len(tlvs))
	cdp[0] = cdpVer
	cdp[1] = cdpTTL
	copy(cdp[4:], tlvs)
	binary.BigEndian.PutUint16(cdp[2:4], cdpChecksum(cdp))

	llcSnap := []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00}
	payloadLen := len(llcSnap) + len(cdp)

	frame := make([]byte, 14+payloadLen)
	copy(frame[0:6], []byte(cdpDstMAC))
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], uint16(payloadLen))
	copy(frame[14:22], llcSnap)
	copy(frame[22:], cdp)
	return frame
}

func tlvString(t uint16, v []byte) []byte {
	b := make([]byte, 4+len(v))
	binary.BigEndian.PutUint16(b[0:2], t)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[4:], v)
	return b
}

func tlvU32(t uint16, v uint32) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], t)
	binary.BigEndian.PutUint16(b[2:4], 8)
	binary.BigEndian.PutUint32(b[4:8], v)
	return b
}

func tlvU16(t uint16, v uint16) []byte {
	b := make([]byte, 6)
	binary.BigEndian.PutUint16(b[0:2], t)
	binary.BigEndian.PutUint16(b[2:4], 6)
	binary.BigEndian.PutUint16(b[4:6], v)
	return b
}

func tlvByte(t uint16, v byte) []byte {
	b := make([]byte, 5)
	binary.BigEndian.PutUint16(b[0:2], t)
	binary.BigEndian.PutUint16(b[2:4], 5)
	b[4] = v
	return b
}

func tlvAddressesZero() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], 0x0002)
	binary.BigEndian.PutUint16(b[2:4], 8)
	return b
}

func cdpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
