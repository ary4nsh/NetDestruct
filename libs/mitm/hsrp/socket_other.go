//go:build !linux

package hsrp

import (
	"fmt"
	"net"
)

type stubSocket struct{}

func openRawSocket(_ *net.Interface) (rawSocket, error) {
	return nil, fmt.Errorf("HSRP hijacking requires Linux with CAP_NET_RAW (root)")
}

func (s *stubSocket) Send([]byte) error { return fmt.Errorf("unsupported platform") }
func (s *stubSocket) Close() error    { return nil }
