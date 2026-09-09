//go:build !linux

package credsniff

import (
	"fmt"
	"net"
	"runtime"
)

type otherSocket struct{}

func openRawSocket(iface *net.Interface) (rawSocket, error) {
	return nil, fmt.Errorf("credential sniffing requires AF_PACKET raw sockets (linux only; current GOOS=%s); cross-compile with GOOS=linux", runtime.GOOS)
}

func (s *otherSocket) Recv(buf []byte) (int, error) { return 0, nil }
func (s *otherSocket) Close() error                 { return nil }
