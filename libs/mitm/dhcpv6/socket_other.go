//go:build !linux

package dhcpv6

import (
	"fmt"
	"net"
	"runtime"
)

type otherSocket struct{}

func openRawSocket(iface *net.Interface) (rawSocket, error) {
	return nil, fmt.Errorf("DHCPv6 spoofing requires AF_PACKET raw sockets (linux only; current GOOS=%s); cross-compile with GOOS=linux", runtime.GOOS)
}

func (s *otherSocket) Send(pkt []byte) error        { return nil }
func (s *otherSocket) Recv(buf []byte) (int, error) { return 0, nil }
func (s *otherSocket) Close() error                 { return nil }
