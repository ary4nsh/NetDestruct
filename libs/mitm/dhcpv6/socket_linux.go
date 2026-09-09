//go:build linux

package dhcpv6

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

const ethPIPv6 = uint16(0x86DD)

type linuxSocket struct {
	fd    int
	ifidx int
	proto uint16
}

// openRawSocket opens AF_PACKET/SOCK_RAW/ETH_P_IPV6 bound to the interface,
// giving full Ethernet frame control so we can target client MACs before
// they have a neighbour-cache entry.
func openRawSocket(iface *net.Interface) (rawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPIPv6)))
	if err != nil {
		return nil, fmt.Errorf("socket(AF_PACKET, SOCK_RAW, ETH_P_IPV6): %w (are you root?)", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(ethPIPv6),
		Ifindex:  iface.Index,
	}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind to %s: %w", iface.Name, err)
	}
	return &linuxSocket{fd: fd, ifidx: iface.Index, proto: htons(ethPIPv6)}, nil
}

// Send transmits the full Ethernet frame as-is; the SockaddrLinklayer only
// needs the interface index for SOCK_RAW (the dst MAC in the frame is used).
func (s *linuxSocket) Send(pkt []byte) error {
	return syscall.Sendto(s.fd, pkt, 0, &syscall.SockaddrLinklayer{
		Protocol: s.proto,
		Ifindex:  s.ifidx,
	})
}

func (s *linuxSocket) Recv(buf []byte) (int, error) {
	n, _, err := syscall.Recvfrom(s.fd, buf, 0)
	return n, err
}

func (s *linuxSocket) Close() error { return syscall.Close(s.fd) }

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.LittleEndian.Uint16(b[:])
}
