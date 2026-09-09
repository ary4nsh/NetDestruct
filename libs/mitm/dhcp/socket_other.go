//go:build !linux

package dhcp

import (
	"fmt"
	"net"
	"runtime"
	"time"
)

// otherSocket is a stub used on non-Linux GOOS targets so the project still
// compiles there (e.g. for local sanity builds on the Windows dev box).
// The real implementation lives in socket_linux.go and is what actually
// ships to the Kali attack box.
type otherSocket struct{}

func openRawSocket(iface *net.Interface) (rawSocket, error) {
	return nil, fmt.Errorf("DHCP spoofing requires raw sockets, which are only implemented for linux (current GOOS=%s); cross-compile with GOOS=linux", runtime.GOOS)
}

func (s *otherSocket) Send(frame []byte) error              { return nil }
func (s *otherSocket) Recv(buf []byte) (int, error)         { return 0, fmt.Errorf("unsupported") }
func (s *otherSocket) SetReadTimeout(d time.Duration) error { return nil }
func (s *otherSocket) Close() error                         { return nil }
