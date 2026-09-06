//go:build !linux

package dhcpflood

import (
	"fmt"
	"net"
	"runtime"
	"time"
)

type otherSocket struct{}

func openRawSocket(iface *net.Interface) (rawSocket, error) {
	return nil, fmt.Errorf("DHCP flooding requires AF_PACKET raw sockets (linux only; current GOOS=%s); cross-compile with GOOS=linux", runtime.GOOS)
}

func (s *otherSocket) Send(frame []byte) error { return nil }
func (s *otherSocket) Recv(buf []byte) (int, error) {
	return 0, fmt.Errorf("recv not supported")
}
func (s *otherSocket) SetReadTimeout(d time.Duration) error { return nil }
func (s *otherSocket) Close() error                         { return nil }
