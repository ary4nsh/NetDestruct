package cdpenum

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type cdpTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

type cdpPacket struct {
	SourceMAC    string
	Version      byte
	TTL          byte
	Checksum     uint16
	ChecksumGood bool
	TLVs         []cdpTLV
}

func parseCDPFrame(frame []byte) (*cdpPacket, bool) {
	if len(frame) < 26 {
		return nil, false
	}
	llcOff, ok := cdpLLCOffset(frame)
	if !ok || len(frame) < llcOff+12 {
		return nil, false
	}
	// 802.3 + LLC/SNAP for CDP.
	if frame[llcOff] != 0xaa || frame[llcOff+1] != 0xaa || frame[llcOff+2] != 0x03 {
		return nil, false
	}
	if frame[llcOff+3] != 0x00 || frame[llcOff+4] != 0x00 || frame[llcOff+5] != 0x0c || frame[llcOff+6] != 0x20 || frame[llcOff+7] != 0x00 {
		return nil, false
	}
	pdu := frame[llcOff+8:]
	if len(pdu) < 4 {
		return nil, false
	}
	recvCsum := binary.BigEndian.Uint16(pdu[2:4])
	tmp := append([]byte{}, pdu...)
	tmp[2], tmp[3] = 0, 0
	good := cdpChecksum(tmp) == recvCsum

	p := &cdpPacket{
		SourceMAC:    fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]),
		Version:      pdu[0],
		TTL:          pdu[1],
		Checksum:     recvCsum,
		ChecksumGood: good,
	}
	off := 4
	for off+4 <= len(pdu) {
		t := binary.BigEndian.Uint16(pdu[off : off+2])
		l := binary.BigEndian.Uint16(pdu[off+2 : off+4])
		if l < 4 || off+int(l) > len(pdu) {
			break
		}
		v := append([]byte{}, pdu[off+4:off+int(l)]...)
		p.TLVs = append(p.TLVs, cdpTLV{Type: t, Length: l, Value: v})
		off += int(l)
		if t == 0x0000 {
			break
		}
	}
	return p, true
}

func cdpLLCOffset(frame []byte) (int, bool) {
	if len(frame) < 18 {
		return 0, false
	}
	off := 12 // starts at Length/Type
	// Skip 802.1Q/802.1ad VLAN tags if present.
	for off+4 <= len(frame) {
		t := binary.BigEndian.Uint16(frame[off : off+2])
		if t != 0x8100 && t != 0x88a8 {
			break
		}
		off += 4
	}
	// After VLAN tags, CDP uses 802.3 length field before LLC.
	if off+2 > len(frame) {
		return 0, false
	}
	return off + 2, true
}

func formatCDP(p *cdpPacket) string {
	var b strings.Builder
	b.WriteString("Cisco Discovery Protocol\n")
	b.WriteString(fmt.Sprintf("    Version: %d\n", p.Version))
	b.WriteString(fmt.Sprintf("    TTL: %d seconds\n", p.TTL))
	b.WriteString(fmt.Sprintf("    Checksum: 0x%04x [%s]\n", p.Checksum, map[bool]string{true: "correct", false: "incorrect"}[p.ChecksumGood]))
	b.WriteString(fmt.Sprintf("    [Checksum Status: %s]\n", map[bool]string{true: "Good", false: "Bad"}[p.ChecksumGood]))

	for _, tlv := range p.TLVs {
		switch tlv.Type {
		case 0x0001:
			v := printable(tlv.Value)
			b.WriteString(fmt.Sprintf("    Device ID: %s\n", v))
			b.WriteString("        Type: Device ID (0x0001)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", tlv.Length))
			b.WriteString(fmt.Sprintf("        Device ID: %s\n", v))
		case 0x0005:
			b.WriteString("    Software Version\n")
			b.WriteString("        Type: Software version (0x0005)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", tlv.Length))
			for _, line := range strings.Split(printable(tlv.Value), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					b.WriteString(fmt.Sprintf("        Software version: %s\n", line))
				}
			}
		case 0x0006:
			v := printable(tlv.Value)
			b.WriteString(fmt.Sprintf("    Platform: %s\n", v))
			b.WriteString("        Type: Platform (0x0006)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", tlv.Length))
			b.WriteString(fmt.Sprintf("        Platform: %s\n", v))
		case 0x0002:
			n := uint32(0)
			if len(tlv.Value) >= 4 {
				n = binary.BigEndian.Uint32(tlv.Value[:4])
			}
			b.WriteString("    Addresses\n")
			b.WriteString("        Type: Addresses (0x0002)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", tlv.Length))
			b.WriteString(fmt.Sprintf("        Number of addresses: %d\n", n))
		case 0x0003:
			v := printable(tlv.Value)
			b.WriteString(fmt.Sprintf("    Port ID: %s\n", v))
			b.WriteString("        Type: Port ID (0x0003)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", tlv.Length))
			b.WriteString(fmt.Sprintf("        Sent through Interface: %s\n", v))
		case 0x0004:
			v := uint32(0)
			if len(tlv.Value) >= 4 {
				v = binary.BigEndian.Uint32(tlv.Value[:4])
			}
			b.WriteString("    Capabilities\n")
			b.WriteString("        Type: Capabilities (0x0004)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", tlv.Length))
			b.WriteString(fmt.Sprintf("        Capabilities: 0x%08x\n", v))
		case 0x0009:
			v := printable(tlv.Value)
			b.WriteString(fmt.Sprintf("    VTP Management Domain: %s\n", v))
			b.WriteString("        Type: VTP Management Domain (0x0009)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", tlv.Length))
			b.WriteString(fmt.Sprintf("        VTP Management Domain: %s\n", v))
		case 0x000a:
			v := uint16(0)
			if len(tlv.Value) >= 2 {
				v = binary.BigEndian.Uint16(tlv.Value[:2])
			}
			b.WriteString(fmt.Sprintf("    Native VLAN: %d\n", v))
			b.WriteString("        Type: Native VLAN (0x000a)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", tlv.Length))
			b.WriteString(fmt.Sprintf("        Native VLAN: %d\n", v))
		case 0x000b:
			duplex := "Half"
			if len(tlv.Value) > 0 && tlv.Value[0] == 1 {
				duplex = "Full"
			}
			b.WriteString(fmt.Sprintf("    Duplex: %s\n", duplex))
			b.WriteString("        Type: Duplex (0x000b)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", tlv.Length))
			b.WriteString(fmt.Sprintf("        Duplex: %s\n", duplex))
		case 0x0012:
			v := byte(0)
			if len(tlv.Value) > 0 {
				v = tlv.Value[0]
			}
			b.WriteString(fmt.Sprintf("    Trust Bitmap: 0x%02x\n", v))
			b.WriteString("        Type: Trust Bitmap (0x0012)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", tlv.Length))
			b.WriteString(fmt.Sprintf("        Trust Bitmap: 0x%02x\n", v))
		case 0x0013:
			v := byte(0)
			if len(tlv.Value) > 0 {
				v = tlv.Value[0]
			}
			b.WriteString(fmt.Sprintf("    Untrusted port CoS: 0x%02x\n", v))
			b.WriteString("        Type: Untrusted Port CoS (0x0013)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", tlv.Length))
			b.WriteString(fmt.Sprintf("        Untrusted port CoS: 0x%02x\n", v))
		case 0x0016:
			n := uint32(0)
			if len(tlv.Value) >= 4 {
				n = binary.BigEndian.Uint32(tlv.Value[:4])
			}
			b.WriteString("    Management Addresses\n")
			b.WriteString("        Type: Management Address (0x0016)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", tlv.Length))
			b.WriteString(fmt.Sprintf("        Number of addresses: %d\n", n))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func printable(b []byte) string {
	s := strings.TrimRight(string(b), "\x00")
	return strings.TrimSpace(s)
}
