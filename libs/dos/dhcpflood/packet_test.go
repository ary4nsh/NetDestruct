package dhcpflood

import (
	"encoding/binary"
	"testing"
)

func TestParsePool(t *testing.T) {
	start, end, err := parsePool("192.168.100.2-254")
	if err != nil {
		t.Fatal(err)
	}
	if intToIP(start) != "192.168.100.2" {
		t.Fatalf("start: %s", intToIP(start))
	}
	if intToIP(end) != "192.168.100.254" {
		t.Fatalf("end: %s", intToIP(end))
	}
}

func TestServerIPFromPool(t *testing.T) {
	start, _, _ := parsePool("192.168.100.2-254")
	got := serverIPFromPool(start)
	if intToIP(got) != "192.168.100.1" {
		t.Fatalf("server IP: %s", intToIP(got))
	}
}

func TestBuildRelease(t *testing.T) {
	var clientMAC, serverMAC [6]byte
	clientMAC[0] = 0xaa
	serverMAC[0] = 0xbb
	clientIP := uint32(0xc0a86402) // 192.168.100.2
	serverIP := uint32(0xc0a86401) // 192.168.100.1

	frame := buildRelease(clientMAC, serverMAC, clientIP, serverIP)
	if len(frame) < 42 {
		t.Fatal("frame too short")
	}
	if frame[0] != serverMAC[0] {
		t.Fatal("eth dst should be server MAC")
	}
	if frame[6] != clientMAC[0] {
		t.Fatal("eth src should be client MAC")
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		t.Fatal("expected IPv4 ethertype")
	}
	ciaddr := binary.BigEndian.Uint32(frame[14+12 : 14+16])
	if ciaddr != clientIP {
		t.Fatalf("ciaddr: %08x", ciaddr)
	}
}

func TestParseARPReply(t *testing.T) {
	var ourMAC, replyMAC [6]byte
	ourMAC[0] = 0x01
	replyMAC[0] = 0xde
	targetIP := uint32(0xc0a86402)

	req := buildARPRequest(ourMAC, 0xc0a86464, targetIP)
	reply := make([]byte, 42)
	copy(reply, req)
	copy(reply[6:12], replyMAC[:]) // Ethernet src = responder
	binary.BigEndian.PutUint16(reply[20:22], arpOpReply)
	copy(reply[22:28], replyMAC[:])
	binary.BigEndian.PutUint32(reply[28:32], targetIP)

	got, ok := parseARPReply(reply, targetIP, ourMAC)
	if !ok {
		t.Fatal("expected ARP reply match")
	}
	if got != replyMAC {
		t.Fatalf("mac mismatch")
	}
}
