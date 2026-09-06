//go:build linux

package tcpflood

import (
	"fmt"
	"net"
	"syscall"
)

type linuxSocket struct {
	fd int
	sa syscall.SockaddrInet4
}

// openRawSocket opens AF_INET/SOCK_RAW/IPPROTO_RAW.
// IPPROTO_RAW implicitly enables IP_HDRINCL so we fully control the IP header,
// enabling source-address spoofing for --random-source mode.
func openRawSocket(iface *net.Interface, target [4]byte) (rawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_INET, SOCK_RAW, IPPROTO_RAW): %w (are you root?)", err)
	}
	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface.Name); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("SO_BINDTODEVICE %s: %w", iface.Name, err)
	}
	return &linuxSocket{fd: fd, sa: syscall.SockaddrInet4{Addr: target}}, nil
}

func (s *linuxSocket) Send(pkt []byte) error {
	return syscall.Sendto(s.fd, pkt, 0, &s.sa)
}

func (s *linuxSocket) Close() error { return syscall.Close(s.fd) }
