package dot1xenum

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const ethTypeDot1X = 0x888e

type Packet struct {
	SourceMAC string
	Body      string
}

type formattedPacket struct {
	SourceMAC string
	Body      string
}

func FormatPacket(frame []byte) (Packet, bool) {
	p, ok := formatPacket(frame)
	if !ok {
		return Packet{}, false
	}
	return Packet{SourceMAC: p.SourceMAC, Body: p.Body}, true
}

func formatPacket(frame []byte) (formattedPacket, bool) {
	sll, payload, ok := extractDot1XPayload(frame)
	if !ok || len(payload) < 4 {
		return formattedPacket{}, false
	}

	srcMAC := sllSourceMAC(sll, frame)
	body := formatDot1XBody(sll, payload, frame)
	return formattedPacket{SourceMAC: srcMAC, Body: body}, true
}

func extractDot1XPayload(frame []byte) (sllHeader, []byte, bool) {
	if isSLL(frame) {
		if len(frame) < 16 {
			return sllHeader{}, nil, false
		}
		proto := binary.BigEndian.Uint16(frame[14:16])
		if proto != ethTypeDot1X {
			return sllHeader{}, nil, false
		}
		return parseSLL(frame), frame[16:], true
	}
	if len(frame) < 18 {
		return sllHeader{}, nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethTypeDot1X {
		return sllHeader{}, nil, false
	}
	return sllHeader{
		PacketType: ethernetPacketType(frame[0:6]),
		AddrType:   1,
		AddrLen:    6,
		Source:     append([]byte{}, frame[6:12]...),
		Protocol:   ethTypeDot1X,
	}, frame[14:], true
}

func ethernetPacketType(dst []byte) uint16 {
	if len(dst) != 6 {
		return 0
	}
	if dst[0] == 0xff && dst[1] == 0xff && dst[2] == 0xff && dst[3] == 0xff && dst[4] == 0xff && dst[5] == 0xff {
		return 1
	}
	if dst[0]&0x01 != 0 {
		return 2
	}
	return 0
}

type sllHeader struct {
	PacketType uint16
	AddrType   uint16
	AddrLen    uint16
	Source     []byte
	Unused     uint16
	Protocol   uint16
}

func parseSLL(frame []byte) sllHeader {
	return sllHeader{
		PacketType: binary.BigEndian.Uint16(frame[0:2]),
		AddrType:   binary.BigEndian.Uint16(frame[2:4]),
		AddrLen:    binary.BigEndian.Uint16(frame[4:6]),
		Source:     append([]byte{}, frame[6:12]...),
		Unused:     binary.BigEndian.Uint16(frame[12:14]),
		Protocol:   binary.BigEndian.Uint16(frame[14:16]),
	}
}

func sllSourceMAC(sll sllHeader, frame []byte) string {
	if len(sll.Source) == 6 {
		return formatMAC(sll.Source)
	}
	if len(frame) >= 12 && !isSLL(frame) {
		return formatMAC(frame[6:12])
	}
	return "unknown"
}

func formatDot1XBody(sll sllHeader, payload, fullFrame []byte) string {
	var b strings.Builder
	b.WriteString("Linux cooked capture v1\n")
	b.WriteString(fmt.Sprintf("    Packet type: %s (%d)\n", sllPacketTypeName(sll.PacketType), sll.PacketType))
	b.WriteString(fmt.Sprintf("    Link-layer address type: %s (%d)\n", sllAddrTypeName(sll.AddrType), sll.AddrType))
	b.WriteString(fmt.Sprintf("    Link-layer address length: %d\n", sll.AddrLen))
	if len(sll.Source) == 6 {
		mac := formatMAC(sll.Source)
		b.WriteString(fmt.Sprintf("    Source: %s (%s)\n", mac, mac))
	}
	b.WriteString(fmt.Sprintf("    Unused: %04x\n", sll.Unused))
	b.WriteString(fmt.Sprintf("    Protocol: 802.1X Authentication (0x%04x)\n", sll.Protocol))

	padding := extractPadding(fullFrame, payload)
	if len(padding) > 0 {
		b.WriteString(fmt.Sprintf("    Padding: %s\n", formatHexSpaced(padding)))
	}

	ver := payload[0]
	typ := payload[1]
	bodyLen := int(binary.BigEndian.Uint16(payload[2:4]))
	eapPayload := payload[4:]
	if bodyLen > 0 && 4+bodyLen <= len(payload) {
		eapPayload = payload[4 : 4+bodyLen]
	}

	b.WriteString("802.1X Authentication\n")
	b.WriteString(fmt.Sprintf("    Version: %s (%d)\n", dot1xVersionName(ver), ver))
	b.WriteString(fmt.Sprintf("    Type: %s (%d)\n", dot1xTypeName(typ), typ))
	b.WriteString(fmt.Sprintf("    Length: %d\n", bodyLen))

	switch typ {
	case 0:
		formatEAP(&b, eapPayload)
	case 1:
		b.WriteString("    EAPOL-Start\n")
	case 2:
		b.WriteString("    EAPOL-Logoff\n")
	case 3:
		formatEAPOLKey(&b, eapPayload)
	default:
		if len(eapPayload) > 0 {
			b.WriteString(fmt.Sprintf("    Data: %s\n", formatHexSpaced(eapPayload)))
		}
	}

	return strings.TrimRight(b.String(), "\n")
}

func formatEAP(b *strings.Builder, data []byte) {
	if len(data) < 4 {
		return
	}
	code := data[0]
	id := data[1]
	eapLen := int(binary.BigEndian.Uint16(data[2:4]))
	if eapLen < 4 {
		eapLen = len(data)
	}
	if eapLen > len(data) {
		eapLen = len(data)
	}
	body := data[4:eapLen]

	b.WriteString("Extensible Authentication Protocol\n")
	b.WriteString(fmt.Sprintf("    Code: %s (%d)\n", eapCodeName(code), code))
	b.WriteString(fmt.Sprintf("    Id: %d\n", id))
	b.WriteString(fmt.Sprintf("    Length: %d\n", eapLen))

	switch code {
	case 1, 2: // Request / Response
		if len(body) >= 1 {
			eapType := body[0]
			b.WriteString(fmt.Sprintf("    Type: %s (%d)\n", eapTypeName(eapType), eapType))
			if len(body) > 1 {
				formatEAPTypeData(b, eapType, body[1:])
			}
		}
	case 3, 4: // Success / Failure
	default:
		if len(body) > 0 {
			b.WriteString(fmt.Sprintf("    Data: %s\n", formatHexSpaced(body)))
		}
	}
}

func formatEAPTypeData(b *strings.Builder, eapType byte, data []byte) {
	switch eapType {
	case 1: // Identity
		if len(data) > 0 {
			b.WriteString(fmt.Sprintf("    Identity: %q\n", string(data)))
		}
	case 2: // Notification
		if len(data) > 0 {
			b.WriteString(fmt.Sprintf("    Notification: %q\n", string(data)))
		}
	case 3: // NAK
		if len(data) > 0 {
			types := make([]string, 0, len(data))
			for _, t := range data {
				types = append(types, fmt.Sprintf("%s (%d)", eapTypeName(t), t))
			}
			b.WriteString(fmt.Sprintf("    Desired types: %s\n", strings.Join(types, ", ")))
		}
	case 4: // MD5-Challenge
		if len(data) >= 1 {
			b.WriteString(fmt.Sprintf("    Value-Size: %d\n", data[0]))
			if len(data) > 1 {
				valSize := int(data[0])
				if valSize > len(data)-1 {
					valSize = len(data) - 1
				}
				if valSize > 0 {
					b.WriteString(fmt.Sprintf("    Value: %s\n", formatHexSpaced(data[1:1+valSize])))
				}
				if len(data) > 1+valSize {
					b.WriteString(fmt.Sprintf("    Name: %q\n", string(data[1+valSize:])))
				}
			}
		}
	case 0x0d: // TLS
		if len(data) >= 1 {
			flags := data[0]
			b.WriteString(fmt.Sprintf("    Flags: 0x%02x", flags))
			if flags&0x20 != 0 {
				b.WriteString(" (Length Included)")
			}
			if flags&0x40 != 0 {
				b.WriteString(" (More Fragments)")
			}
			if flags&0x80 != 0 {
				b.WriteString(" (Start)")
			}
			b.WriteString("\n")
			off := 1
			if flags&0x20 != 0 && len(data) >= 5 {
				tlsLen := int(binary.BigEndian.Uint32(data[1:5]))
				b.WriteString(fmt.Sprintf("    TLS Length: %d\n", tlsLen))
				off = 5
			}
			if off < len(data) {
				b.WriteString(fmt.Sprintf("    TLS Data: %s\n", formatHexSpaced(data[off:])))
			}
		}
	case 0x11: // LEAP (Cisco)
		if len(data) >= 2 {
			ver := data[0]
			role := data[1]
			b.WriteString(fmt.Sprintf("    LEAP Version: %d\n", ver))
			b.WriteString(fmt.Sprintf("    LEAP Role: %s (%d)\n", leapRoleName(role), role))
			if len(data) > 2 {
				b.WriteString(fmt.Sprintf("    LEAP Data: %s\n", formatHexSpaced(data[2:])))
			}
		}
	case 0x19: // PEAP
		if len(data) >= 1 {
			flags := data[0]
			b.WriteString(fmt.Sprintf("    Flags: 0x%02x\n", flags))
			if len(data) > 1 {
				b.WriteString(fmt.Sprintf("    PEAP Data: %s\n", formatHexSpaced(data[1:])))
			}
		}
	case 0x15: // TTLS
		if len(data) >= 1 {
			flags := data[0]
			b.WriteString(fmt.Sprintf("    Flags: 0x%02x\n", flags))
			if len(data) > 1 {
				b.WriteString(fmt.Sprintf("    TTLS Data: %s\n", formatHexSpaced(data[1:])))
			}
		}
	case 0xfe: // Expanded
		if len(data) >= 4 {
			vendor := binary.BigEndian.Uint32(data[0:4])
			b.WriteString(fmt.Sprintf("    Vendor-ID: 0x%08x\n", vendor))
			if len(data) > 4 {
				b.WriteString(fmt.Sprintf("    Vendor-Type: %d\n", data[4]))
				if len(data) > 5 {
					b.WriteString(fmt.Sprintf("    Vendor-Data: %s\n", formatHexSpaced(data[5:])))
				}
			}
		}
	default:
		if len(data) > 0 {
			b.WriteString(fmt.Sprintf("    Type-Data: %s\n", formatHexSpaced(data)))
		}
	}
}

func formatEAPOLKey(b *strings.Builder, data []byte) {
	if len(data) == 0 {
		return
	}
	b.WriteString("    EAPOL-Key\n")
	if len(data) >= 1 {
		desc := data[0]
		b.WriteString(fmt.Sprintf("    Key Descriptor Type: %s (%d)\n", eapolKeyDescName(desc), desc))
	}
	if len(data) >= 2 {
		info := binary.BigEndian.Uint16(data[1:3])
		b.WriteString(fmt.Sprintf("    Key Information: 0x%04x\n", info))
	}
	if len(data) > 3 {
		b.WriteString(fmt.Sprintf("    Key Data: %s\n", formatHexSpaced(data[3:])))
	}
}

func extractPadding(fullFrame, payload []byte) []byte {
	if isSLL(fullFrame) {
		end := 16 + len(payload)
		if end >= len(fullFrame) {
			return nil
		}
		pad := fullFrame[end:]
		if allZero(pad) {
			return pad
		}
		return pad
	}
	end := 14 + len(payload)
	if end >= len(fullFrame) {
		return nil
	}
	return fullFrame[end:]
}

func isSLL(frame []byte) bool {
	if len(frame) < 16 {
		return false
	}
	pktType := binary.BigEndian.Uint16(frame[0:2])
	if pktType > 4 {
		return false
	}
	return binary.BigEndian.Uint16(frame[2:4]) == 1 &&
		binary.BigEndian.Uint16(frame[4:6]) == 6
}

func formatMAC(mac []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func formatHexSpaced(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, "")
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func sllPacketTypeName(t uint16) string {
	switch t {
	case 0:
		return "Unicast to us"
	case 1:
		return "Broadcast"
	case 2:
		return "Multicast"
	case 3:
		return "Sent by us"
	case 4:
		return "Sent by someone else"
	default:
		return "Unknown"
	}
}

func sllAddrTypeName(t uint16) string {
	switch t {
	case 0:
		return "None"
	case 1:
		return "Ethernet"
	default:
		return "Unknown"
	}
}

func dot1xVersionName(v byte) string {
	switch v {
	case 1:
		return "802.1X-2001"
	case 2:
		return "802.1X-2004"
	case 3:
		return "802.1X-2010"
	default:
		return fmt.Sprintf("Unknown 802.1X version")
	}
}

func dot1xTypeName(t byte) string {
	switch t {
	case 0:
		return "EAP Packet"
	case 1:
		return "EAPOL-Start"
	case 2:
		return "EAPOL-Logoff"
	case 3:
		return "EAPOL-Key"
	case 4:
		return "EAPOL-Encapsulated-ASF-Alert"
	default:
		return fmt.Sprintf("Unknown EAPOL type")
	}
}

func eapCodeName(c byte) string {
	switch c {
	case 1:
		return "Request"
	case 2:
		return "Response"
	case 3:
		return "Success"
	case 4:
		return "Failure"
	default:
		return "Unknown"
	}
}

func eapTypeName(t byte) string {
	switch t {
	case 1:
		return "Identity"
	case 2:
		return "Notification"
	case 3:
		return "NAK"
	case 4:
		return "MD5-Challenge"
	case 5:
		return "OTP"
	case 6:
		return "GTC"
	case 13:
		return "TLS"
	case 17:
		return "LEAP"
	case 21:
		return "TTLS"
	case 25:
		return "PEAP"
	case 254:
		return "Expanded Types"
	case 255:
		return "Experimental"
	default:
		return fmt.Sprintf("Unknown type")
	}
}

func leapRoleName(r byte) string {
	switch r {
	case 1:
		return "Challenge"
	case 2:
		return "Response"
	case 3:
		return "Success"
	default:
		return "Unknown"
	}
}

func eapolKeyDescName(d byte) string {
	switch d {
	case 1:
		return "RC4 Key"
	case 2:
		return "WPA Key"
	case 254:
		return "WPA2 Key"
	default:
		return "Unknown"
	}
}
