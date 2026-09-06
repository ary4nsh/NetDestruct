package stpflood

import (
	"encoding/binary"
	"testing"
)

func TestBuildConfFrame(t *testing.T) {
	var mac [6]byte
	mac[0] = 0x02
	mac[5] = 0xab
	frame := buildConfFrame(mac, 0x8000, 0x9000)
	if len(frame) != 14+3+35 {
		t.Fatalf("frame length %d", len(frame))
	}
	if frame[0] != 0x01 || frame[5] != 0x00 {
		t.Fatal("expected STP multicast dst")
	}
	if frame[6] != mac[0] {
		t.Fatal("eth src mismatch")
	}
	bpdu := frame[14+3:]
	if bpdu[3] != bpduConfSTP {
		t.Fatalf("bpdu type %02x", bpdu[3])
	}
	if bpdu[4] != stpTopologyChange {
		t.Fatalf("flags %02x", bpdu[4])
	}
	if binary.BigEndian.Uint16(bpdu[5:7]) != 0x8000 {
		t.Fatal("root priority")
	}
}

func TestBuildTCNFrame(t *testing.T) {
	var mac [6]byte
	mac[0] = 0x02
	frame := buildTCNFrame(mac)
	if len(frame) != 14+3+4 {
		t.Fatalf("frame length %d", len(frame))
	}
	bpdu := frame[14+3:]
	if bpdu[2] != stpVersion {
		t.Fatalf("version %02x", bpdu[2])
	}
	if bpdu[3] != bpduTCN {
		t.Fatalf("bpdu type %02x", bpdu[3])
	}
}
