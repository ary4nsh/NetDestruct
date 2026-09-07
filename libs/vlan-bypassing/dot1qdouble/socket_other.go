//go:build !linux

package dot1qdouble

import (
	"fmt"
	"net"
	"runtime"
)

type otherSocket struct{}

func openRawSocket(_ *net.Interface) (rawSocket, error) {
	return nil, fmt.Errorf("802.1Q double-tag requires AF_PACKET raw sockets (linux only; current GOOS=%s); cross-compile with GOOS=linux", runtime.GOOS)
}

func (s *otherSocket) Send(_ []byte) error                { return nil }
func (s *otherSocket) Recv(_ []byte) (int, uint16, error) { return 0, 0, nil }
func (s *otherSocket) Close() error                     { return nil }
