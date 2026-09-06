//go:build !linux

package ospf

import (
	"fmt"
	"net"
	"runtime"
)

type otherSocket struct{}

func openRawSocket(iface *net.Interface) (rawSocket, error) {
	return nil, fmt.Errorf("OSPF blackhole requires AF_PACKET raw sockets (linux only; current GOOS=%s)", runtime.GOOS)
}
