//go:build linux

package dhcpflood

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

type linuxSocket struct{ fd int }

func htons(v uint16) uint16 { return (v<<8)&0xff00 | (v>>8)&0x00ff }

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
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s.fd),
		syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
		uintptr(unsafe.Pointer(&tv)), unsafe.Sizeof(tv), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (s *linuxSocket) Close() error { return syscall.Close(s.fd) }
