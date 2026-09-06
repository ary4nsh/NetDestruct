//go:build linux

package icmpflood

import (
	"fmt"
	"net"
	"syscall"
)

type linuxSocket struct {
	fd int
	sa syscall.SockaddrInet4
}

// openRawSocket opens an AF_INET/SOCK_RAW/IPPROTO_RAW socket.
// IPPROTO_RAW implicitly enables IP_HDRINCL so we control the full IP header,
// including the source address for --random-source mode.
// The kernel handles routing and Ethernet framing — no destination MAC needed.
func openRawSocket(iface *net.Interface, target [4]byte) (rawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_INET, SOCK_RAW, IPPROTO_RAW): %w (are you root?)", err)
	}
	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface.Name); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("SO_BINDTODEVICE %s: %w", iface.Name, err)
	}
	sa := syscall.SockaddrInet4{Addr: target}
	return &linuxSocket{fd: fd, sa: sa}, nil
}

func (s *linuxSocket) Send(pkt []byte) error {
	return syscall.Sendto(s.fd, pkt, 0, &s.sa)
}

func (s *linuxSocket) Close() error { return syscall.Close(s.fd) }
