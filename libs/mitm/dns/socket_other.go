//go:build !linux

package dns

import (
	"fmt"
	"net"
	"time"
)

type captureSocket struct{}
type rawSocket struct{}

func openCaptureSocket(_ *net.Interface) (*captureSocket, error) {
	return nil, fmt.Errorf("DNS hijacking requires Linux with CAP_NET_RAW (root)")
}

func (s *captureSocket) Recv([]byte) (int, error) { return 0, fmt.Errorf("unsupported platform") }
func (s *captureSocket) SetReadTimeout(time.Duration) error { return nil }
func (s *captureSocket) Close() error                       { return nil }

func openRawSocket(_ *net.Interface) (*rawSocket, error) {
	return nil, fmt.Errorf("DNS hijacking requires Linux with CAP_NET_RAW (root)")
}

func openRawSocket6(_ *net.Interface) (*rawSocket, error) {
	return nil, fmt.Errorf("DNS hijacking requires Linux with CAP_NET_RAW (root)")
}

func (s *rawSocket) Send([]byte, net.IP) error  { return fmt.Errorf("unsupported platform") }
func (s *rawSocket) Send6([]byte, net.IP) error { return fmt.Errorf("unsupported platform") }
func (s *rawSocket) Close() error               { return nil }
