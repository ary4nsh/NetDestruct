package dhcpenum

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

func formatDHCPv4(iface string, m *dhcpv4Msg) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("  Interface: %s\n", iface))
	b.WriteString(fmt.Sprintf("  Transaction ID: 0x%08x\n", m.xid))
	if m.yiaddr != nil && !m.yiaddr.Equal(net.IPv4zero) {
		b.WriteString(fmt.Sprintf("  Your IP Address (yiaddr): %s\n", m.yiaddr))
	}
	if m.siaddr != nil && !m.siaddr.Equal(net.IPv4zero) {
		b.WriteString(fmt.Sprintf("  Server IP Address (siaddr): %s\n", m.siaddr))
	}
	if m.serverIP != nil && !m.serverIP.Equal(net.IPv4zero) {
		b.WriteString(fmt.Sprintf("  DHCP Server: %s\n", m.serverIP))
	}
	if m.serverMAC != "" {
		b.WriteString(fmt.Sprintf("  Server MAC: %s\n", m.serverMAC))
	}
	if block := formatOptionBlock("DHCP Options", formatDHCPv4OptionLines(m.optionList)); block != "" {
		b.WriteString(block)
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatDHCPv6(iface string, m *dhcpv6Msg) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("  Interface: %s\n", iface))
	b.WriteString(fmt.Sprintf("  Message Type: %s\n", dhcpv6MsgTypeName(m.msgType)))
	b.WriteString(fmt.Sprintf("  Transaction ID: 0x%06x\n", tridToUint(m.trid)))
	if m.srcIP != nil {
		b.WriteString(fmt.Sprintf("  Server Address: %s\n", m.srcIP))
	}
	if m.serverMAC != "" {
		b.WriteString(fmt.Sprintf("  Server MAC: %s\n", m.serverMAC))
	}
	if block := formatOptionBlock("DHCPv6 Options", formatDHCPv6OptionLines(m.optionList)); block != "" {
		b.WriteString(block)
	}
	return strings.TrimRight(b.String(), "\n")
}

func dhcpv4MsgTypeName(t byte) string {
	switch t {
	case 1:
		return "DISCOVER"
	case 2:
		return "DHCPOFFER"
	case 3:
		return "REQUEST"
	case 4:
		return "DECLINE"
	case 5:
		return "DHCPACK"
	case 6:
		return "DHCPNAK"
	case 7:
		return "RELEASE"
	case 8:
		return "INFORM"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

func dhcpv6MsgTypeName(t byte) string {
	switch t {
	case 1:
		return "Solicit"
	case 2:
		return "Advertise"
	case 3:
		return "Request"
	case 4:
		return "Confirm"
	case 5:
		return "Renew"
	case 6:
		return "Rebind"
	case 7:
		return "Reply"
	case 8:
		return "Release"
	case 9:
		return "Decline"
	case 10:
		return "Reconfigure"
	case 11:
		return "Information-Request"
	case 12:
		return "Relay-Forward"
	case 13:
		return "Relay-Reply"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

func formatIPv4List(raw []byte) string {
	var ips []string
	for i := 0; i+4 <= len(raw); i += 4 {
		ips = append(ips, net.IP(raw[i:i+4]).String())
	}
	return strings.Join(ips, ", ")
}

func formatIPv6List(raw []byte) string {
	var ips []string
	for i := 0; i+16 <= len(raw); i += 16 {
		ips = append(ips, net.IP(raw[i:i+16]).String())
	}
	return strings.Join(ips, ", ")
}

func formatHex(raw []byte) string {
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

func formatDUID(raw []byte) string {
	if len(raw) < 2 {
		return formatHex(raw)
	}
	duidType := binary.BigEndian.Uint16(raw[0:2])
	switch duidType {
	case 1:
		if len(raw) >= 8 {
			hw := binary.BigEndian.Uint16(raw[2:4])
			ts := binary.BigEndian.Uint32(raw[4:8])
			if len(raw) > 8 {
				return fmt.Sprintf("DUID-LLT hw-type %d time %d addr %s", hw, ts, formatHex(raw[8:]))
			}
			return fmt.Sprintf("DUID-LLT hw-type %d time %d", hw, ts)
		}
		return "DUID-LLT " + formatHex(raw)
	case 2:
		if len(raw) >= 6 {
			ent := binary.BigEndian.Uint32(raw[2:6])
			return fmt.Sprintf("DUID-EN enterprise %d %s", ent, formatHex(raw[6:]))
		}
		return "DUID-EN " + formatHex(raw)
	case 3:
		if len(raw) >= 10 {
			hw := binary.BigEndian.Uint16(raw[2:4])
			return fmt.Sprintf("DUID-LL hw-type %d %s", hw, net.HardwareAddr(raw[4:10]))
		}
	case 4:
		return "DUID-UUID " + formatHex(raw[2:])
	}
	return formatHex(raw)
}

func tridToUint(t [3]byte) uint32 {
	return uint32(t[0])<<16 | uint32(t[1])<<8 | uint32(t[2])
}
