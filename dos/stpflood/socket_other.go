//go:build !linux

package stpflood

import (
	"fmt"
	"net"
	"runtime"
)

type otherSocket struct{}

func openRawSocket(iface *net.Interface) (rawSocket, error) {
	return nil, fmt.Errorf("STP flooding requires AF_PACKET raw sockets (linux only; current GOOS=%s); cross-compile with GOOS=linux", runtime.GOOS)
}

func (s *otherSocket) Send(frame []byte) error { return nil }
func (s *otherSocket) Close() error            { return nil }
