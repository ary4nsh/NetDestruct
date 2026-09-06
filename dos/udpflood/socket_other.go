//go:build !linux

package udpflood

import (
	"fmt"
	"net"
	"runtime"
)

type otherSocket struct{}

func openRawSocket(iface *net.Interface, target [4]byte) (rawSocket, error) {
	return nil, fmt.Errorf("UDP flooding requires AF_INET raw sockets (linux only; current GOOS=%s); cross-compile with GOOS=linux", runtime.GOOS)
}

func (s *otherSocket) Send(pkt []byte) error { return nil }
func (s *otherSocket) Close() error          { return nil }
