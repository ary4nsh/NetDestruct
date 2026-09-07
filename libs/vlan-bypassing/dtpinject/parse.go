package dtpinject

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type dtpTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

type dtpPacket struct {
	SourceMAC   string
	Version     byte
	TLVs        []dtpTLV
	TrunkStatus byte
	TrunkType   byte
	SenderID    string
}

func parseDTPFrame(frame []byte) (*dtpPacket, bool) {
	if len(frame) < 23 {
		return nil, false
	}
	llcOff, ok := dtpLLCOffset(frame)
	if !ok || len(frame) < llcOff+9 {
		return nil, false
	}
	if frame[llcOff] != 0xaa || frame[llcOff+1] != 0xaa || frame[llcOff+2] != 0x03 {
		return nil, false
	}
	if frame[llcOff+3] != 0x00 || frame[llcOff+4] != 0x00 || frame[llcOff+5] != 0x0c || frame[llcOff+6] != 0x20 || frame[llcOff+7] != 0x04 {
		return nil, false
	}
	d := frame[llcOff+8:]
	if len(d) < 1 {
		return nil, false
	}
	p := &dtpPacket{
		SourceMAC: fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]),
		Version:   d[0],
	}
	off := 1
	for off+4 <= len(d) {
		t := binary.BigEndian.Uint16(d[off : off+2])
		l := binary.BigEndian.Uint16(d[off+2 : off+4])
		if t == 0x0000 || l == 0 {
			p.TLVs = append(p.TLVs, dtpTLV{Type: t, Length: l})
			break
		}
		if l < 4 || off+int(l) > len(d) {
			break
		}
		v := append([]byte{}, d[off+4:off+int(l)]...)
		tlv := dtpTLV{Type: t, Length: l, Value: v}
		p.TLVs = append(p.TLVs, tlv)
		switch t {
		case 0x0002:
			if len(v) > 0 {
				p.TrunkStatus = v[0]
			}
		case 0x0003:
			if len(v) > 0 {
				p.TrunkType = v[0]
			}
		case 0x0004:
			if len(v) >= 6 {
				p.SenderID = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", v[0], v[1], v[2], v[3], v[4], v[5])
			}
		}
		off += int(l)
	}
	return p, true
}

func dtpLLCOffset(frame []byte) (int, bool) {
	if len(frame) < 18 {
		return 0, false
	}
	off := 12
	for off+4 <= len(frame) {
		t := binary.BigEndian.Uint16(frame[off : off+2])
		if t != 0x8100 && t != 0x88a8 {
			break
		}
		off += 4
	}
	if off+2 > len(frame) {
		return 0, false
	}
	return off + 2, true
}

func formatDTP(p *dtpPacket) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Dynamic Trunk Protocol:  (Operating/Administrative): %s (0x%02x) (Operating/Administrative): %s (0x%02x): %s\n",
		dtpStatusLabel(p.TrunkStatus), p.TrunkStatus, dtpTypeLabel(p.TrunkType), p.TrunkType, zeroIfEmpty(p.SenderID)))
	b.WriteString(fmt.Sprintf("    Version: %d\n", p.Version))
	for _, t := range p.TLVs {
		switch t.Type {
		case 0x0001:
			v := printable(t.Value)
			b.WriteString("    Domain\n")
			b.WriteString("        Type: Domain (0x0001)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", t.Length))
			b.WriteString(fmt.Sprintf("        Domain: %s\n", v))
		case 0x0002:
			val := byte(0)
			if len(t.Value) > 0 {
				val = t.Value[0]
			}
			b.WriteString("    Trunk Status\n")
			b.WriteString("        Type: Trunk Status (0x0002)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", t.Length))
			b.WriteString(fmt.Sprintf("        Value: %s (0x%02x)\n", dtpStatusLabel(val), val))
		case 0x0003:
			val := byte(0)
			if len(t.Value) > 0 {
				val = t.Value[0]
			}
			b.WriteString("    Trunk Type\n")
			b.WriteString("        Type: Trunk Type (0x0003)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", t.Length))
			b.WriteString(fmt.Sprintf("        Value: %s (0x%02x)\n", dtpTypeLabel(val), val))
		case 0x0004:
			sid := ""
			if len(t.Value) >= 6 {
				sid = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", t.Value[0], t.Value[1], t.Value[2], t.Value[3], t.Value[4], t.Value[5])
			}
			b.WriteString("    Sender ID\n")
			b.WriteString("        Type: Sender ID (0x0004)\n")
			b.WriteString(fmt.Sprintf("        Length: %d\n", t.Length))
			b.WriteString(fmt.Sprintf("        Sender ID: %s (%s)\n", sid, sid))
		default:
			b.WriteString(fmt.Sprintf("    Unknown TLV type: 0x%02x\n", t.Type&0x00ff))
			b.WriteString(fmt.Sprintf("        Type: Unknown (0x%04x)\n", t.Type))
			b.WriteString(fmt.Sprintf("        Length: %d\n", t.Length))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func dtpStatusLabel(v byte) string {
	switch v {
	case 0x81:
		return "Trunk/On"
	case 0x83:
		return "Trunk/Desirable"
	case 0x84:
		return "Access/Auto"
	case 0xa5:
		return "Access/On"
	default:
		return "Unknown"
	}
}

func dtpTypeLabel(v byte) string {
	switch v {
	case 0xa0:
		return "802.1Q/Negotiated"
	case 0xa5:
		return "802.1Q"
	case 0x00:
		return "ISL"
	default:
		return "Unknown"
	}
}

func printable(v []byte) string { return strings.TrimRight(string(v), "\x00") }
func zeroIfEmpty(s string) string {
	if s == "" {
		return "00:00:00:00:00:00"
	}
	return s
}
