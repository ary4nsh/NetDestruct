//go:build !linux

package arp

import (
	"fmt"
	"net"
	"time"
)

type stubSocket struct{}

func openRawSocket(_ *net.Interface) (rawSocket, error) {
	return nil, fmt.Errorf("ARP cage requires Linux with CAP_NET_RAW (root)")
}

func (s *stubSocket) Send([]byte) error         { return fmt.Errorf("unsupported platform") }
func (s *stubSocket) Recv([]byte) (int, error)  { return 0, fmt.Errorf("unsupported platform") }
func (s *stubSocket) SetReadTimeout(time.Duration) error { return nil }
func (s *stubSocket) Close() error              { return nil }
