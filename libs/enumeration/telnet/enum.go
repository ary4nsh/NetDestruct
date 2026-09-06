package telnet

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	// Dark green [TELNET] tag.
	telnetTag      = "\x1b[32m[TELNET]\x1b[0m"
	defaultPort    = 23
	defaultTimeout = 8 * time.Second

	iac  = 0xff
	sb   = 0xfa
	se   = 0xf0
	will = 0xfb
	wont = 0xfc
	doCmd = 0xfd
	dont = 0xfe

	optEncrypt = 0x26 // TELOPT ENCRYPT
	optAuth    = 0x25 // TELOPT AUTHENTICATION
)

// Enumerator runs telnet discovery: banner, Telnet Encryption, Telnet NTLM Information.
type Enumerator struct {
	Target  string
	Port    int
	Timeout time.Duration
	Out     io.Writer
}

// Run connects to the Telnet service and prints banner + encryption + NTLM info.
func (e *Enumerator) Run() error {
	host := strings.TrimSpace(e.Target)
	if host == "" {
		return fmt.Errorf("--telnet --enum requires --target <ip>")
	}
	port := e.Port
	if port <= 0 {
		port = defaultPort
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	out := e.Out
	if out == nil {
		out = os.Stdout
	}

	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.LookupIP(host)
		if err != nil || len(addrs) == 0 {
			return fmt.Errorf("resolve %q: %w", host, err)
		}
		ip = addrs[0]
	}
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	fmt.Fprintf(out, "%s Target: %s\n", telnetTag, addr)

	banner, err := grabBanner(addr, timeout)
	if err != nil {
		return err
	}
	if banner != "" {
		fmt.Fprintf(out, "%s Banner: %s\n", telnetTag, banner)
	} else {
		fmt.Fprintf(out, "%s Banner: (none)\n", telnetTag)
	}

	encMsg, err := probeEncryption(addr, timeout)
	if err != nil {
		fmt.Fprintf(out, "\n%s Telnet Encryption: %v\n", telnetTag, err)
	} else {
		fmt.Fprintf(out, "\n%s Telnet Encryption:\n", telnetTag)
		fmt.Fprintf(out, "      %s\n", encMsg)
	}

	ntlm, err := probeNTLMInfo(addr, timeout)
	if err != nil {
		fmt.Fprintf(out, "\n%s Telnet NTLM Information: %v\n", telnetTag, err)
	} else if ntlm == nil {
		fmt.Fprintf(out, "\n%s Telnet NTLM Information:\n", telnetTag)
		fmt.Fprintf(out, "      (no NTLM challenge / MS-TNAP info)\n")
	} else {
		fmt.Fprintf(out, "\n%s Telnet NTLM Information:\n", telnetTag)
		printNTLM(out, ntlm)
	}
	return nil
}

func grabBanner(addr string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", fmt.Errorf("connect %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			// Reply WONT/DONT to options so Cisco/login banners often follow.
			if reply := refuseOptions(tmp[:n]); len(reply) > 0 {
				_, _ = conn.Write(reply)
			}
			if text := stripIAC(buf); strings.TrimSpace(text) != "" && !mostlyBinary(text) {
				// Keep reading a bit more if we only have negotiation so far.
				if len(text) > 8 || strings.ContainsAny(text, "\n\r") {
					break
				}
			}
		}
		if err != nil {
			break
		}
	}
	return cleanBanner(stripIAC(buf)), nil
}

func refuseOptions(data []byte) []byte {
	var out []byte
	i := 0
	for i < len(data) {
		if data[i] != iac {
			i++
			continue
		}
		if i+1 >= len(data) {
			break
		}
		cmd := data[i+1]
		switch cmd {
		case will:
			if i+2 >= len(data) {
				return out
			}
			out = append(out, iac, dont, data[i+2])
			i += 3
		case doCmd:
			if i+2 >= len(data) {
				return out
			}
			out = append(out, iac, wont, data[i+2])
			i += 3
		case wont, dont:
			i += 3
		case sb:
			i += 2
			for i < len(data)-1 {
				if data[i] == iac && data[i+1] == se {
					i += 2
					break
				}
				i++
			}
		default:
			i += 2
		}
	}
	return out
}

func stripIAC(data []byte) string {
	var b strings.Builder
	i := 0
	for i < len(data) {
		if data[i] != iac {
			b.WriteByte(data[i])
			i++
			continue
		}
		if i+1 >= len(data) {
			break
		}
		cmd := data[i+1]
		switch cmd {
		case will, wont, doCmd, dont:
			i += 3
		case sb:
			i += 2
			for i < len(data)-1 {
				if data[i] == iac && data[i+1] == se {
					i += 2
					break
				}
				i++
			}
		case iac: // escaped 0xFF
			b.WriteByte(iac)
			i += 2
		default:
			i += 2
		}
	}
	return b.String()
}

func cleanBanner(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	var keep []string
	for _, ln := range lines {
		ln = strings.TrimRight(ln, " \t")
		if strings.TrimSpace(ln) == "" {
			continue
		}
		keep = append(keep, ln)
	}
	out := strings.Join(keep, " | ")
	out = strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, out)
	return strings.TrimSpace(out)
}

func mostlyBinary(s string) bool {
	if s == "" {
		return true
	}
	bad := 0
	for _, r := range s {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			bad++
		}
	}
	return bad*2 > len(s)
}

// probeEncryption: Telnet Encryption
// send DO ENCRYPT + WILL ENCRYPT (FF FD 26 FF FB 26), look for WILL/DO on option 0x26.
func probeEncryption(addr string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte{iac, doCmd, optEncrypt, iac, will, optEncrypt}); err != nil {
		return "", fmt.Errorf("send: %w", err)
	}

	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 1024)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			cmds := optionCommands(buf, optEncrypt)
			for _, c := range cmds {
				if c == will || c == doCmd {
					return "Telnet server supports encryption", nil
				}
			}
			// Non-option trailing data means negotiation finished without ENCRYPT.
			if hasNonOptionData(buf) && len(cmds) == 0 {
				break
			}
			if len(cmds) > 0 {
				// Got some response for 0x26 that wasn't WILL/DO (e.g. WONT/DONT).
				for _, c := range cmds {
					if c == wont || c == dont {
						return "Telnet server does not support encryption", nil
					}
				}
			}
		}
		if err != nil {
			break
		}
	}
	cmds := optionCommands(buf, optEncrypt)
	for _, c := range cmds {
		if c == will || c == doCmd {
			return "Telnet server supports encryption", nil
		}
	}
	return "Telnet server does not support encryption", nil
}

func optionCommands(data []byte, option byte) []byte {
	var cmds []byte
	i := 0
	for i < len(data) {
		if data[i] != iac {
			i++
			continue
		}
		if i+1 >= len(data) {
			break
		}
		cmd := data[i+1]
		if cmd == sb {
			i += 2
			for i < len(data)-1 {
				if data[i] == iac && data[i+1] == se {
					i += 2
					break
				}
				i++
			}
			continue
		}
		if i+2 >= len(data) {
			break
		}
		opt := data[i+2]
		if opt == option {
			cmds = append(cmds, cmd)
		}
		i += 3
	}
	return cmds
}

func hasNonOptionData(data []byte) bool {
	i := 0
	for i < len(data) {
		if data[i] != iac {
			return true
		}
		if i+1 >= len(data) {
			return false
		}
		cmd := data[i+1]
		if cmd == sb {
			i += 2
			for i < len(data)-1 {
				if data[i] == iac && data[i+1] == se {
					i += 2
					break
				}
				i++
			}
			continue
		}
		i += 3
	}
	return false
}

type ntlmInfo struct {
	TargetName         string
	NetBIOSDomainName  string
	NetBIOSComputerName string
	DNSDomainName      string
	DNSComputerName    string
	DNSTreeName        string
	ProductVersion     string
}

func printNTLM(out io.Writer, n *ntlmInfo) {
	const indent = "      "
	kv := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			fmt.Fprintf(out, "%s%s: %s\n", indent, k, v)
		}
	}
	kv("Target_Name", n.TargetName)
	kv("NetBIOS_Domain_Name", n.NetBIOSDomainName)
	kv("NetBIOS_Computer_Name", n.NetBIOSComputerName)
	kv("DNS_Domain_Name", n.DNSDomainName)
	kv("DNS_Computer_Name", n.DNSComputerName)
	kv("DNS_Tree_Name", n.DNSTreeName)
	kv("Product_Version", n.ProductVersion)
}

// probeNTLMInfo mirrors Telnet NTLM Information (MS-TNAP + NTLM Type 1 negotiate).
func probeNTLMInfo(addr string, timeout time.Duration) (*ntlmInfo, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Drain any initial banner/negotiation briefly.
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	pre := make([]byte, 2048)
	_, _ = conn.Read(pre)
	_ = conn.SetDeadline(time.Now().Add(timeout))

	pkt := buildTNAPNegotiate()
	if _, err := conn.Write(pkt); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}

	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 2048)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if info := parseTNAPNTLM(buf); info != nil {
				return info, nil
			}
		}
		if err != nil {
			break
		}
	}
	return parseTNAPNTLM(buf), nil
}

func buildTNAPNegotiate() []byte {
	// Flags from Telnet NTLM Information.
	const flags = uint32(
		0x00000001 | // Negotiate Unicode
			0x00000002 | // Negotiate OEM
			0x00000004 | // Request Target
			0x00000200 | // Negotiate NTLM
			0x00008000 | // Negotiate Always Sign
			0x00080000 | // Negotiate NTLM2 Key
			0x20000000 | // Negotiate 128
			0x80000000) // Negotiate 56

	ntlm := make([]byte, 32)
	copy(ntlm[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(ntlm[8:12], 1) // NEGOTIATE
	binary.LittleEndian.PutUint32(ntlm[12:16], flags)
	// Domain / Workstation fields remain zero (length/max/offset as I8 each).

	var pkt []byte
	pkt = append(pkt,
		iac, sb, optAuth,
		0x00, // Auth IS
		0x0f, // Auth Type NTLM
		0x00, // Who: client→server
		0x00, // NTLM_NEGOTIATE
	)
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(ntlm)))
	pkt = append(pkt, lenBuf[:]...)
	pkt = append(pkt, 0x02, 0x00, 0x00, 0x00) // NTLM_BufferType
	pkt = append(pkt, ntlm...)
	pkt = append(pkt, iac, se)
	return pkt
}

func parseTNAPNTLM(data []byte) *ntlmInfo {
	// match "(NTLMSSP.*)\xff\xf0"
	start := indexNTLMSSP(data)
	if start < 0 {
		return nil
	}
	end := -1
	for i := start; i+1 < len(data); i++ {
		if data[i] == iac && data[i+1] == se {
			end = i
			break
		}
	}
	var blob []byte
	if end > start {
		blob = data[start:end]
	} else {
		blob = data[start:]
	}
	return parseNTLMChallenge(blob)
}

func indexNTLMSSP(b []byte) int {
	sig := []byte("NTLMSSP\x00")
	for i := 0; i+len(sig) <= len(b); i++ {
		match := true
		for j := 0; j < len(sig); j++ {
			if b[i+j] != sig[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func parseNTLMChallenge(msg []byte) *ntlmInfo {
	if len(msg) < 32 {
		return nil
	}
	if string(msg[0:8]) != "NTLMSSP\x00" {
		return nil
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != 2 {
		return nil
	}

	info := &ntlmInfo{}
	info.TargetName = readNTLMUTF16(msg, 12)

	flags := binary.LittleEndian.Uint32(msg[20:24])
	if len(msg) >= 48 {
		infoLen := int(binary.LittleEndian.Uint16(msg[40:42]))
		infoOff := int(binary.LittleEndian.Uint32(msg[44:48]))
		if infoLen > 0 && infoOff >= 0 && infoOff+infoLen <= len(msg) {
			parseAvPairs(msg[infoOff:infoOff+infoLen], info)
		}
	}

	// Product version when Negotiate Version (0x02000000) is set.
	if flags&0x02000000 != 0 && len(msg) >= 56 {
		major, minor := msg[48], msg[49]
		build := binary.LittleEndian.Uint16(msg[50:52])
		info.ProductVersion = fmt.Sprintf("%d.%d.%d", major, minor, build)
	}

	// Target_Name is always shown when present.
	if info.TargetName == "" && info.NetBIOSDomainName == "" &&
		info.NetBIOSComputerName == "" && info.DNSComputerName == "" &&
		info.ProductVersion == "" {
		return nil
	}
	return info
}

func readNTLMUTF16(msg []byte, fieldOff int) string {
	if fieldOff+8 > len(msg) {
		return ""
	}
	length := int(binary.LittleEndian.Uint16(msg[fieldOff : fieldOff+2]))
	offset := int(binary.LittleEndian.Uint32(msg[fieldOff+4 : fieldOff+8]))
	if length <= 0 || offset < 0 || offset+length > len(msg) {
		return ""
	}
	return utf16LEBytesToString(msg[offset : offset+length])
}

func parseAvPairs(raw []byte, info *ntlmInfo) {
	i := 0
	for i+4 <= len(raw) {
		avID := binary.LittleEndian.Uint16(raw[i : i+2])
		avLen := int(binary.LittleEndian.Uint16(raw[i+2 : i+4]))
		i += 4
		if avID == 0 { // MsvAvEOL
			break
		}
		if i+avLen > len(raw) {
			break
		}
		val := utf16LEBytesToString(raw[i : i+avLen])
		switch avID {
		case 1: // MsvAvNbComputerName
			info.NetBIOSComputerName = val
		case 2: // MsvAvNbDomainName
			info.NetBIOSDomainName = val
		case 3: // MsvAvDnsComputerName
			info.DNSComputerName = val
		case 4: // MsvAvDnsDomainName
			info.DNSDomainName = val
		case 5: // MsvAvDnsTreeName
			info.DNSTreeName = val
		}
		i += avLen
	}
}

func utf16LEBytesToString(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := 0; i < len(u); i++ {
		u[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u))
}
