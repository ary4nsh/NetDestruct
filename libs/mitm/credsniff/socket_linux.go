//go:build linux

package credsniff

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

const ethPAll = uint16(0x0003) // ETH_P_ALL — capture every Layer-2 frame

type linuxRawSocket struct {
	fd int
}

func openRawSocket(iface *net.Interface) (rawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("socket(AF_PACKET, SOCK_RAW, ETH_P_ALL): %w (are you root?)", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  iface.Index,
	}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind to %s: %w", iface.Name, err)
	}
	return &linuxRawSocket{fd: fd}, nil
}

func (s *linuxRawSocket) Recv(buf []byte) (int, error) {
	n, _, err := syscall.Recvfrom(s.fd, buf, 0)
	return n, err
}

func (s *linuxRawSocket) Close() error { return syscall.Close(s.fd) }

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.LittleEndian.Uint16(b[:])
}
