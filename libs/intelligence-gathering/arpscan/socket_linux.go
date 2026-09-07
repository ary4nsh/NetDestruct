//go:build linux

package arpscan

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

const ethPARP = uint16(0x0806)

type linuxARPSocket struct {
	fd    int
	ifidx int
	proto uint16
}

// openARPSocket opens AF_PACKET/SOCK_RAW/ETH_P_ARP and binds it to the
// given interface for ARP injection and sniffing.
func openARPSocket(iface *net.Interface) (arpSocket, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPARP)))
	if err != nil {
		return nil, fmt.Errorf("socket(AF_PACKET, SOCK_RAW, ETH_P_ARP): %w (are you root?)", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(ethPARP),
		Ifindex:  iface.Index,
	}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind to %s: %w", iface.Name, err)
	}
	return &linuxARPSocket{fd: fd, ifidx: iface.Index, proto: htons(ethPARP)}, nil
}

func (s *linuxARPSocket) Send(pkt []byte) error {
	return syscall.Sendto(s.fd, pkt, 0, &syscall.SockaddrLinklayer{
		Protocol: s.proto,
		Ifindex:  s.ifidx,
		Halen:    6,
		Addr:     [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	})
}

func (s *linuxARPSocket) Recv(buf []byte) (int, error) {
	n, _, err := syscall.Recvfrom(s.fd, buf, 0)
	return n, err
}

func (s *linuxARPSocket) Close() error { return syscall.Close(s.fd) }

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.LittleEndian.Uint16(b[:])
}
