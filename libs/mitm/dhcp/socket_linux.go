//go:build linux

package dhcp

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

// linuxSocket is a Linux AF_PACKET/SOCK_RAW socket bound to one interface.
// DHCP replies must reach a client that has no IP yet (DHCPv4) or must
// bypass normal routing to go straight to the client's MAC (DHCPv6), so
// (like libs/arp) we craft full Ethernet frames ourselves instead of using
// net.ListenUDP.
type linuxSocket struct {
	fd int
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0x00ff
}

// openRawSocket opens an AF_PACKET/SOCK_RAW socket bound to iface, capturing
// every EtherType (ETH_P_ALL) so the caller can filter DHCP traffic itself.
// Requires CAP_NET_RAW (root).
func openRawSocket(iface *net.Interface) (rawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(uint16(syscall.ETH_P_ALL))))
	if err != nil {
		return nil, fmt.Errorf("socket(AF_PACKET): %w (are you root?)", err)
	}
	sa := &syscall.SockaddrLinklayer{
		Protocol: htons(uint16(syscall.ETH_P_ALL)),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind %s: %w", iface.Name, err)
	}
	return &linuxSocket{fd: fd}, nil
}

func (s *linuxSocket) Send(frame []byte) error {
	_, err := syscall.Write(s.fd, frame)
	return err
}

func (s *linuxSocket) Recv(buf []byte) (int, error) {
	return syscall.Read(s.fd, buf)
}

func (s *linuxSocket) SetReadTimeout(d time.Duration) error {
	tv := syscall.NsecToTimeval(d.Nanoseconds())
	return syscall.SetsockoptTimeval(s.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
}

func (s *linuxSocket) Close() error {
	return syscall.Close(s.fd)
}
