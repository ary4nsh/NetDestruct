//go:build !linux

package cdpinject

import (
	"fmt"
	"net"
	"runtime"
)

type otherSocket struct{}

func openRawSocket(_ *net.Interface) (rawSocket, error) {
	return nil, fmt.Errorf("CDP injection requires AF_PACKET raw sockets (linux only; current GOOS=%s); cross-compile with GOOS=linux", runtime.GOOS)
}

func (s *otherSocket) Send(_ []byte) error { return nil }
func (s *otherSocket) Close() error        { return nil }
