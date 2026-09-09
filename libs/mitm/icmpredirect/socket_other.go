//go:build !linux

package icmpredirect

import (
	"fmt"
	"net"
	"time"
)

type stubSocket struct{}

func openRawSocket(_ *net.Interface) (rawSocket, error) {
	return nil, fmt.Errorf("ICMP redirect requires Linux with CAP_NET_RAW (root)")
}

func (s *stubSocket) Send([]byte, net.IP) error { return fmt.Errorf("unsupported platform") }
func (s *stubSocket) Close() error             { return nil }

type stubCaptureSocket struct{}

func openCaptureSocket(_ *net.Interface) (captureSocket, error) {
	return &stubCaptureSocket{}, nil
}

func (s *stubCaptureSocket) Recv([]byte) (int, error) { return 0, fmt.Errorf("unsupported platform") }
func (s *stubCaptureSocket) SetReadTimeout(time.Duration) error { return nil }
func (s *stubCaptureSocket) Close() error                       { return nil }
