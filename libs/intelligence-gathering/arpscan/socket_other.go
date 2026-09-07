//go:build !linux

package arpscan

import (
	"fmt"
	"net"
	"runtime"
)

type otherARPSocket struct{}

func openARPSocket(iface *net.Interface) (arpSocket, error) {
	return nil, fmt.Errorf("ARP scanning requires AF_PACKET raw sockets (linux only; current GOOS=%s); cross-compile with GOOS=linux", runtime.GOOS)
}

func (s *otherARPSocket) Send(pkt []byte) error        { return nil }
func (s *otherARPSocket) Recv(buf []byte) (int, error) { return 0, nil }
func (s *otherARPSocket) Close() error                 { return nil }
