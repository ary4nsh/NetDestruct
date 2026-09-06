//go:build !linux

package vtpcrash

import (
	"fmt"
	"net"
	"runtime"
)

type otherSocket struct{}

func openRawSocket(_ *net.Interface) (rawSocket, error) {
	return nil, fmt.Errorf("VTP delete-all requires AF_PACKET raw sockets (linux only; current GOOS=%s); cross-compile with GOOS=linux", runtime.GOOS)
}

func (s *otherSocket) Send(_ []byte) error        { return nil }
func (s *otherSocket) Recv(_ []byte) (int, error) { return 0, nil }
func (s *otherSocket) Close() error               { return nil }
