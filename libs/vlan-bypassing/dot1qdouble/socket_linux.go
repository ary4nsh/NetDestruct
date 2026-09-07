//go:build linux

package dot1qdouble

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const packetAuxData = 8

const tpStatusVLANValid = 1 << 4

type linuxSocket struct {
	fd int
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | (v>>8)&0x00ff }

func openRawSocket(iface *net.Interface) (rawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(uint16(syscall.ETH_P_ALL))))
	if err != nil {
		return nil, fmt.Errorf("socket(AF_PACKET): %w (are you root?)", err)
	}
	sa := &syscall.SockaddrLinklayer{
		Protocol: htons(uint16(syscall.ETH_P_ALL)),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind %s: %w", iface.Name, err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetAuxData, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("PACKET_AUXDATA on %s: %w", iface.Name, err)
	}
	if err := setPromiscuous(iface.Name, true); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("enable promiscuous capture on %s: %w", iface.Name, err)
	}
	return &linuxSocket{fd: fd}, nil
}

func (s *linuxSocket) Send(frame []byte) error {
	_, err := syscall.Write(s.fd, frame)
	return err
}

func (s *linuxSocket) Recv(buf []byte) (int, uint16, error) {
	oob := make([]byte, 256)
	for {
		n, oobn, _, _, err := syscall.Recvmsg(s.fd, buf, oob, 0)
		if err != nil {
			return 0, 0, err
		}
		if n == 0 {
			continue
		}
		return n, parseStrippedVLAN(oob[:oobn]), nil
	}
}

func (s *linuxSocket) Close() error { return syscall.Close(s.fd) }

func parseStrippedVLAN(oob []byte) uint16 {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, m := range msgs {
		if m.Header.Level != syscall.SOL_PACKET || m.Header.Type != packetAuxData {
			continue
		}
		if len(m.Data) < 20 {
			continue
		}
		status := binary.LittleEndian.Uint32(m.Data[0:4])
		tpid := binary.LittleEndian.Uint16(m.Data[18:20])
		tci := binary.LittleEndian.Uint16(m.Data[16:18])
		if status&tpStatusVLANValid != 0 {
			return tci
		}
		if tpid == 0x8100 || tpid == 0x88a8 {
			return tci
		}
	}
	return 0
}

type ifreqFlags struct {
	Name  [syscall.IFNAMSIZ]byte
	Flags uint16
	Pad   [22]byte
}

func setPromiscuous(ifaceName string, enable bool) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	var ifr ifreqFlags
	copy(ifr.Name[:], ifaceName)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return errno
	}
	if enable {
		ifr.Flags |= syscall.IFF_PROMISC
	} else {
		ifr.Flags &^= syscall.IFF_PROMISC
	}
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return errno
	}
	return nil
}
