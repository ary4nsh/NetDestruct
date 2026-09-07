//go:build !linux

package dhcpenum

import (
	"fmt"
	"net"
	"runtime"
)

type otherSocket struct{}

func openRawSocket(iface *net.Interface) (rawSocket, error) {
	return nil, fmt.Errorf("DHCP enumeration requires AF_PACKET raw sockets (linux only; current GOOS=%s); cross-compile with GOOS=linux", runtime.GOOS)
}

func (s *otherSocket) Send(frame []byte) error { return nil }
func (s *otherSocket) Recv(buf []byte) (int, error) {
	return 0, fmt.Errorf("recv not supported")
}
func (s *otherSocket) Close() error { return nil }
