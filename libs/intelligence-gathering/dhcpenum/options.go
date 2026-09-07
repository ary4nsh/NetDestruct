package dhcpenum

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

type dhcpOption struct {
	Code byte
	Data []byte
}

type dhcpv6Option struct {
	Code uint16
	Data []byte
}

// dhcpv4OptionName returns option names (RFC 2132).
func dhcpv4OptionName(code byte) string {
	if int(code) < len(dhcpv4OptionNames) && dhcpv4OptionNames[code] != "" {
		return dhcpv4OptionNames[code]
	}
	return fmt.Sprintf("Option %d", code)
}

var dhcpv4OptionNames = [256]string{
	0:   "Padding",
	1:   "Subnet Mask",
	2:   "Time Offset",
	3:   "Router",
	4:   "Time Server",
	5:   "Name Server",
	6:   "Domain Name Server",
	7:   "Log Server",
	8:   "Quotes Server",
	9:   "LPR Server",
	10:  "Impress Server",
	11:  "Resource Location Server",
	12:  "Host Name",
	13:  "Boot File Size",
	14:  "Merit Dump File",
	15:  "Domain Name",
	16:  "Swap Server",
	17:  "Root Path",
	18:  "Extensions Path",
	19:  "IP Forwarding",
	20:  "Non-Local Source Routing",
	21:  "Policy Filter",
	22:  "Maximum Datagram Reassembly Size",
	23:  "Default IP Time-to-Live",
	24:  "Path MTU Aging Timeout",
	25:  "Path MTU Plateau Table",
	26:  "Interface MTU",
	27:  "All Subnets are Local",
	28:  "Broadcast Address",
	29:  "Perform Mask Discovery",
	30:  "Mask Supplier",
	31:  "Perform Router Discover",
	32:  "Router Solicitation Address",
	33:  "Static Route",
	34:  "Trailer Encapsulation",
	35:  "ARP Cache Timeout",
	36:  "Ethernet Encapsulation",
	37:  "TCP Default TTL",
	38:  "TCP Keepalive Interval",
	39:  "TCP Keepalive Garbage",
	40:  "Network Information Service Domain",
	41:  "Network Information Service Servers",
	42:  "Network Time Protocol Servers",
	43:  "Vendor-Specific Information",
	44:  "NetBIOS over TCP/IP Name Server",
	45:  "NetBIOS over TCP/IP Datagram Distribution Name Server",
	46:  "NetBIOS over TCP/IP Node Type",
	47:  "NetBIOS over TCP/IP Scope",
	48:  "X Window System Font Server",
	49:  "X Window System Display Manager",
	50:  "Requested IP Address",
	51:  "IP Address Lease Time",
	52:  "Option Overload",
	53:  "DHCP Message Type",
	54:  "DHCP Server Identifier",
	55:  "Parameter Request List",
	56:  "Message",
	57:  "Maximum DHCP Message Size",
	58:  "Renewal Time Value",
	59:  "Rebinding Time Value",
	60:  "Vendor class identifier",
	61:  "Client identifier",
	62:  "Novell/Netware IP domain",
	63:  "Novell Options",
	64:  "Network Information Service+ Domain",
	65:  "Network Information Service+ Servers",
	66:  "TFTP Server Name",
	67:  "Bootfile name",
	68:  "Mobile IP Home Agent",
	69:  "SMTP Server",
	70:  "POP3 Server",
	71:  "NNTP Server",
	72:  "Default WWW Server",
	73:  "Default Finger Server",
	74:  "Default IRC Server",
	75:  "StreetTalk Server",
	76:  "StreetTalk Directory Assistance Server",
	77:  "User Class Information",
	78:  "Directory Agent Information",
	79:  "Service Location Agent Scope",
	80:  "Rapid commit",
	81:  "Client Fully Qualified Domain Name",
	82:  "Agent Information Option",
	83:  "iSNS",
	86:  "Novell Directory Services Tree Name",
	87:  "Novell Directory Services Context",
	91:  "Client last transaction time",
	92:  "Associated IP option",
	93:  "Client System Architecture",
	94:  "Client Network Device Interface",
	97:  "UUID/GUID-based Client Identifier",
	100: "PCode",
	101: "TCode",
	108: "IPv6-Only Preferred",
	112: "NetInfo Parent Server Address",
	113: "NetInfo Parent Server Tag",
	114: "DHCP Captive-Portal",
	116: "DHCP Auto-Configuration",
	117: "Name Service Search",
	118: "Subnet Selection Option",
	119: "Domain Search",
	120: "SIP Servers",
	121: "Classless Static Route",
	122: "CableLabs Client Configuration",
	123: "Coordinate-based Location Configuration",
	124: "V-I Vendor Class",
	125: "V-I Vendor-specific Information",
	136: "PANA Authentication Agent",
	137: "LoST Server Domain Name",
	138: "CAPWAP Access Controllers",
	142: "IPv4 Address ANDSF",
	146: "RDNSS Selection",
	150: "TFTP Server Address",
	161: "Manufacturer Usage Description",
}

func decodeDHCPv4Option(code byte, data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	switch code {
	case optMsgType:
		if len(data) == 1 {
			return []string{dhcpv4MsgTypeName(data[0])}
		}
	case optSubnetMask, 16, 28, 32, 50, optServerID:
		if len(data) == 4 {
			return []string{net.IP(data).String()}
		}
	case optRouter, optDNS, 4, 5, 7, 8, 9, 10, 11, 41, 42, 44, 45, 48, 49, 65, 68, 69, 70, 71, 72, 73, 74, 75, 76, 92, 112, 118, 136, 138, 142, 150:
		if len(data)%4 == 0 {
			return []string{formatIPv4List(data)}
		}
	case optHostName, optDomainName, 14, 17, 18, 40, 47, 56, 66, 67, 62, 64, 86, 87, 100, 101, 113, 137, 161:
		return []string{printableString(data)}
	case optLeaseTime, 24, 35, 38, 58, 59, 91, 108:
		if len(data) == 4 {
			return []string{fmt.Sprintf("%d seconds", binary.BigEndian.Uint32(data))}
		}
	case 2:
		if len(data) == 4 {
			return []string{fmt.Sprintf("%d seconds", int32(binary.BigEndian.Uint32(data)))}
		}
	case 13, 22, 26, 57:
		if len(data) == 2 {
			return []string{fmt.Sprintf("%d", binary.BigEndian.Uint16(data))}
		}
	case 23, 37, 46, 116:
		if len(data) == 1 {
			return []string{fmt.Sprintf("%d", data[0])}
		}
	case 19, 20, 27, 29, 30, 31, 34, 36, 39:
		if len(data) == 1 {
			return []string{dhcpBoolean(data[0])}
		}
	case 25:
		return decodeU16List(data)
	case 52:
		if len(data) == 1 {
			switch data[0] {
			case 1:
				return []string{"file"}
			case 2:
				return []string{"sname"}
			case 3:
				return []string{"file, sname"}
			default:
				return []string{fmt.Sprintf("%d", data[0])}
			}
		}
	case 55:
		return decodeParamRequestList(data)
	case optClientID, 97:
		return decodeClientID(data)
	case 60:
		return []string{printableString(data)}
	case 77:
		return decodeUserClass(data)
	case 119:
		if s := formatDomainSearchList(data); s != "" {
			return []string{s}
		}
	case 121:
		return decodeClasslessStaticRoute(data)
	case 82:
		return decodeRelayAgentInfo(data)
	case 43, 125:
		return decodeVendorSpecific(data)
	default:
		if len(data)%4 == 0 && looksLikeIPv4List(data) {
			return []string{formatIPv4List(data)}
		}
		if isPrintable(data) {
			return []string{printableString(data)}
		}
	}
	return []string{formatHex(data)}
}

func dhcpv6OptionName(code uint16) string {
	if name, ok := dhcpv6OptionNames[code]; ok {
		return name
	}
	return fmt.Sprintf("Option %d", code)
}

var dhcpv6OptionNames = map[uint16]string{
	1:   "Client Identifier",
	2:   "Server Identifier",
	3:   "Identity Association for Non-temporary Address",
	4:   "Identity Association for Temporary Address",
	5:   "IA Address",
	6:   "Option Request",
	7:   "Preference",
	8:   "Elapsed time",
	9:   "Relay Message",
	11:  "Authentication",
	12:  "Server unicast",
	13:  "Status code",
	14:  "Rapid Commit",
	15:  "User Class",
	16:  "Vendor Class",
	17:  "Vendor-specific Information",
	18:  "Interface-Id",
	19:  "Reconfigure Message",
	20:  "Reconfigure Accept",
	21:  "SIP Server Domain Name List",
	22:  "SIP Servers IPv6 Address List",
	23:  "DNS recursive name server",
	24:  "Domain Search List",
	25:  "Identity Association for Prefix Delegation",
	26:  "IA Prefix",
	27:  "Network Information Server",
	28:  "Network Information Server V2",
	29:  "Network Information Server Domain Name",
	30:  "Network Information Server V2 Domain Name",
	31:  "Simple Network Time Protocol Server",
	39:  "Client Fully Qualified Domain Name",
	41:  "Time Zone",
	59:  "Boot File URL",
	61:  "Client System Architecture Type",
	62:  "Client Network Interface Identifier",
	79:  "Client Link-Layer Address",
}

func decodeDHCPv6Option(code uint16, data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	switch code {
	case opt6ClientID, opt6ServerID:
		return []string{formatDUID(data)}
	case opt6IANA, 4:
		return decodeIANAOption(data)
	case opt6IAAddr:
		return decodeIAAddrOption(data)
	case 6, 39:
		return decodeORO(data)
	case 7:
		if len(data) == 1 {
			return []string{fmt.Sprintf("%d", data[0])}
		}
	case 8:
		if len(data) == 2 {
			return []string{fmt.Sprintf("%d centiseconds", binary.BigEndian.Uint16(data))}
		}
	case 13:
		return decodeStatusCode(data)
	case 23, 22, 27, 28, 31:
		if len(data)%16 == 0 {
			return []string{formatIPv6List(data)}
		}
	case opt6DomainSrch, 21, 29, 30:
		if s := formatDomainSearchList(data); s != "" {
			return []string{s}
		}
	case 16:
		return decodeVendorClass(data)
	case 17:
		return decodeVendorOpts(data)
	case 79:
		if len(data) >= 2 {
			linkType := binary.BigEndian.Uint16(data[0:2])
			if len(data) == 8 && linkType == 1 {
				return []string{net.HardwareAddr(data[2:8]).String()}
			}
			return []string{fmt.Sprintf("link-type %d, data %s", linkType, formatHex(data[2:]))}
		}
	case 26:
		return decodeIAPrefix(data)
	default:
		if len(data)%16 == 0 && len(data) >= 16 && looksLikeIPv6List(data) {
			return []string{formatIPv6List(data)}
		}
		if isPrintable(data) {
			return []string{printableString(data)}
		}
	}
	return []string{formatHex(data)}
}

func decodeParamRequestList(data []byte) []string {
	parts := make([]string, 0, len(data))
	for _, c := range data {
		parts = append(parts, fmt.Sprintf("%d (%s)", c, dhcpv4OptionName(c)))
	}
	return []string{strings.Join(parts, ", ")}
}

func decodeClientID(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	switch data[0] {
	case 0:
		if len(data) == 7 {
			return []string{fmt.Sprintf("Ethernet %s", net.HardwareAddr(data[1:7]))}
		}
	case 1:
		return []string{fmt.Sprintf("IAID-DUID %s", formatHex(data[1:]))}
	}
	return []string{formatHex(data)}
}

func decodeUserClass(data []byte) []string {
	var out []string
	for i := 0; i < len(data); {
		if i+1 >= len(data) {
			break
		}
		l := int(data[i])
		i++
		if l == 0 || i+l > len(data) {
			break
		}
		out = append(out, printableString(data[i:i+l]))
		i += l
	}
	if len(out) == 0 {
		return []string{formatHex(data)}
	}
	return out
}

func decodeClasslessStaticRoute(data []byte) []string {
	var routes []string
	for i := 0; i < len(data); {
		if i >= len(data) {
			break
		}
		prefixLen := int(data[i])
		i++
		byteLen := (prefixLen + 7) / 8
		if i+byteLen+4 > len(data) {
			break
		}
		network := cidrFromBytes(prefixLen, data[i:i+byteLen])
		i += byteLen
		gw := net.IP(data[i : i+4])
		i += 4
		routes = append(routes, fmt.Sprintf("%s via %s", network, gw))
	}
	if len(routes) == 0 {
		return []string{formatHex(data)}
	}
	return routes
}

func decodeRelayAgentInfo(data []byte) []string {
	var lines []string
	for i := 0; i+2 <= len(data); {
		sub := data[i]
		l := int(data[i+1])
		i += 2
		if i+l > len(data) {
			break
		}
		val := data[i : i+l]
		i += l
		switch sub {
		case 1:
			lines = append(lines, fmt.Sprintf("Agent Circuit ID: %s", formatHex(val)))
		case 2:
			lines = append(lines, fmt.Sprintf("Agent Remote ID: %s", formatHex(val)))
		case 5:
			if len(val) == 4 {
				lines = append(lines, fmt.Sprintf("Link Selection: %s", net.IP(val)))
			}
		case 6:
			lines = append(lines, fmt.Sprintf("Subscriber ID: %s", printableString(val)))
		default:
			lines = append(lines, fmt.Sprintf("Suboption %d: %s", sub, formatHex(val)))
		}
	}
	if len(lines) == 0 {
		return []string{formatHex(data)}
	}
	return lines
}

func decodeVendorSpecific(data []byte) []string {
	if len(data) < 4 {
		return []string{formatHex(data)}
	}
	ent := binary.BigEndian.Uint32(data[0:4])
	rest := data[4:]
	if len(rest) == 0 {
		return []string{fmt.Sprintf("Enterprise %d", ent)}
	}
	if isPrintable(rest) {
		return []string{fmt.Sprintf("Enterprise %d: %s", ent, printableString(rest))}
	}
	return []string{fmt.Sprintf("Enterprise %d: %s", ent, formatHex(rest))}
}

func decodeIANAOption(data []byte) []string {
	if len(data) < 12 {
		return []string{formatHex(data)}
	}
	lines := []string{
		fmt.Sprintf("IAID: 0x%08x", binary.BigEndian.Uint32(data[0:4])),
		fmt.Sprintf("T1: %d seconds", binary.BigEndian.Uint32(data[4:8])),
		fmt.Sprintf("T2: %d seconds", binary.BigEndian.Uint32(data[8:12])),
	}
	for sub := data[12:]; len(sub) >= 4; {
		code := binary.BigEndian.Uint16(sub[0:2])
		l := int(binary.BigEndian.Uint16(sub[2:4]))
		if 4+l > len(sub) {
			break
		}
		val := sub[4 : 4+l]
		name := dhcpv6OptionName(code)
		for _, line := range decodeDHCPv6Option(code, val) {
			lines = append(lines, fmt.Sprintf("%s: %s", name, line))
		}
		sub = sub[4+l:]
	}
	return lines
}

func decodeIAAddrOption(data []byte) []string {
	if len(data) < 16 {
		return []string{formatHex(data)}
	}
	addr := net.IP(data[0:16]).String()
	if len(data) >= 24 {
		pref := binary.BigEndian.Uint32(data[16:20])
		valid := binary.BigEndian.Uint32(data[20:24])
		return []string{fmt.Sprintf("%s (preferred %d, valid %d)", addr, pref, valid)}
	}
	return []string{addr}
}

func decodeIAPrefix(data []byte) []string {
	if len(data) < 25 {
		return []string{formatHex(data)}
	}
	prefLT := binary.BigEndian.Uint32(data[0:4])
	validLT := binary.BigEndian.Uint32(data[4:8])
	prefixLen := data[8]
	prefix := cidrFromBytes(int(prefixLen), data[9:25])
	return []string{
		fmt.Sprintf("Preferred lifetime: %d seconds", prefLT),
		fmt.Sprintf("Valid lifetime: %d seconds", validLT),
		fmt.Sprintf("Prefix: %s", prefix),
	}
}

func decodeORO(data []byte) []string {
	if len(data)%2 != 0 {
		return []string{formatHex(data)}
	}
	parts := make([]string, 0, len(data)/2)
	for i := 0; i+2 <= len(data); i += 2 {
		code := binary.BigEndian.Uint16(data[i : i+2])
		parts = append(parts, fmt.Sprintf("%d (%s)", code, dhcpv6OptionName(code)))
	}
	return []string{strings.Join(parts, ", ")}
}

func decodeStatusCode(data []byte) []string {
	if len(data) < 2 {
		return []string{formatHex(data)}
	}
	code := binary.BigEndian.Uint16(data[0:2])
	msg := string(data[2:])
	if msg == "" {
		return []string{fmt.Sprintf("code %d", code)}
	}
	return []string{fmt.Sprintf("code %d: %s", code, msg)}
}

func decodeVendorClass(data []byte) []string {
	var out []string
	for i := 0; i+4 <= len(data); {
		ent := binary.BigEndian.Uint32(data[i : i+4])
		i += 4
		if i+2 > len(data) {
			break
		}
		l := int(binary.BigEndian.Uint16(data[i : i+2]))
		i += 2
		if i+l > len(data) {
			break
		}
		out = append(out, fmt.Sprintf("Enterprise %d: %s", ent, printableString(data[i:i+l])))
		i += l
	}
	if len(out) == 0 {
		return []string{formatHex(data)}
	}
	return out
}

func decodeVendorOpts(data []byte) []string {
	if len(data) < 4 {
		return []string{formatHex(data)}
	}
	ent := binary.BigEndian.Uint32(data[0:4])
	rest := data[4:]
	if len(rest) == 0 {
		return []string{fmt.Sprintf("Enterprise %d", ent)}
	}
	return []string{fmt.Sprintf("Enterprise %d: %s", ent, formatHex(rest))}
}

func decodeU16List(data []byte) []string {
	if len(data)%2 != 0 {
		return []string{formatHex(data)}
	}
	parts := make([]string, 0, len(data)/2)
	for i := 0; i+2 <= len(data); i += 2 {
		parts = append(parts, fmt.Sprintf("%d", binary.BigEndian.Uint16(data[i:i+2])))
	}
	return []string{strings.Join(parts, ", ")}
}

func dhcpBoolean(v byte) string {
	if v == 0 {
		return "Disabled"
	}
	return "Enabled"
}

func printableString(data []byte) string {
	return strings.TrimRight(string(data), "\x00")
}

func isPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		if b < 0x20 || b > 0x7e {
			if b != 0 {
				return false
			}
		}
	}
	return true
}

func looksLikeIPv4List(data []byte) bool {
	return len(data) >= 4 && len(data)%4 == 0
}

func looksLikeIPv6List(data []byte) bool {
	return len(data) >= 16 && len(data)%16 == 0
}

func formatDomainSearchList(raw []byte) string {
	var domains []string
	for i := 0; i < len(raw); {
		l := int(raw[i])
		i++
		if l == 0 {
			break
		}
		if i+l > len(raw) {
			break
		}
		labels := make([]string, 0, 4)
		start := i
		for j := start; j < start+l; {
			ll := int(raw[j])
			j++
			if ll == 0 || j+ll > start+l {
				break
			}
			labels = append(labels, string(raw[j:j+ll]))
			j += ll
		}
		if len(labels) > 0 {
			domains = append(domains, strings.Join(labels, "."))
		}
		i += l
	}
	return strings.Join(domains, ", ")
}

func cidrFromBytes(prefixLen int, raw []byte) string {
	ip := make(net.IP, 16)
	copy(ip[16-len(raw):], raw)
	if prefixLen <= 32 && len(raw) <= 4 {
		v4 := make(net.IP, 4)
		copy(v4[4-len(raw):], raw)
		return fmt.Sprintf("%s/%d", v4, prefixLen)
	}
	return fmt.Sprintf("%s/%d", ip, prefixLen)
}

func formatOptionBlock(title string, lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("  %s:\n", title))
	for _, line := range lines {
		b.WriteString(fmt.Sprintf("    %s\n", line))
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatDHCPv4OptionLines(opts []dhcpOption) []string {
	lines := make([]string, 0, len(opts))
	for _, opt := range opts {
		if opt.Code == 0 {
			continue
		}
		name := dhcpv4OptionName(opt.Code)
		decoded := decodeDHCPv4Option(opt.Code, opt.Data)
		header := fmt.Sprintf("Option %d (%s)", opt.Code, name)
		if len(decoded) == 0 {
			lines = append(lines, header)
			continue
		}
		if len(decoded) == 1 {
			lines = append(lines, fmt.Sprintf("%s: %s", header, decoded[0]))
			continue
		}
		lines = append(lines, header+":")
		for _, d := range decoded {
			lines = append(lines, "  "+d)
		}
	}
	return lines
}

func formatDHCPv6OptionLines(opts []dhcpv6Option) []string {
	lines := make([]string, 0, len(opts))
	for _, opt := range opts {
		name := dhcpv6OptionName(opt.Code)
		decoded := decodeDHCPv6Option(opt.Code, opt.Data)
		header := fmt.Sprintf("Option %d (%s)", opt.Code, name)
		if len(decoded) == 0 {
			lines = append(lines, header)
			continue
		}
		if len(decoded) == 1 {
			lines = append(lines, fmt.Sprintf("%s: %s", header, decoded[0]))
			continue
		}
		lines = append(lines, header+":")
		for _, d := range decoded {
			lines = append(lines, "  "+d)
		}
	}
	return lines
}
