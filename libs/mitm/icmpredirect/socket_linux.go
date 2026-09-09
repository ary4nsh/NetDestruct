//go:build linux

package icmpredirect

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

type linuxSocket struct {
	fd int
}

func openRawSocket(iface *net.Interface) (rawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_INET, SOCK_RAW, IPPROTO_RAW): %w (are you root?)", err)
	}
	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface.Name); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("SO_BINDTODEVICE %s: %w", iface.Name, err)
	}
	return &linuxSocket{fd: fd}, nil
}

func (s *linuxSocket) Send(pkt []byte, dst net.IP) error {
	v4 := dst.To4()
	if v4 == nil {
		return fmt.Errorf("IPv4 destination required")
	}
	sa := &syscall.SockaddrInet4{Addr: [4]byte{v4[0], v4[1], v4[2], v4[3]}}
	return syscall.Sendto(s.fd, pkt, 0, sa)
}

func (s *linuxSocket) Close() error { return syscall.Close(s.fd) }

type linuxCaptureSocket struct{ fd int }

func htons(v uint16) uint16 { return (v<<8)&0xff00 | (v>>8)&0x00ff }

func openCaptureSocket(iface *net.Interface) (captureSocket, error) {
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
	return &linuxCaptureSocket{fd: fd}, nil
}

func (s *linuxCaptureSocket) Recv(buf []byte) (int, error) {
	return syscall.Read(s.fd, buf)
}

func (s *linuxCaptureSocket) SetReadTimeout(d time.Duration) error {
	tv := syscall.NsecToTimeval(d.Nanoseconds())
	return syscall.SetsockoptTimeval(s.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
}

func (s *linuxCaptureSocket) Close() error { return syscall.Close(s.fd) }
