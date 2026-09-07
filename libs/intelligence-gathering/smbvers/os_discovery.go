package smbvers

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

type smbOSDiscovery struct {
	OS                 string
	LanManager         string
	CPE                string
	ComputerName       string
	NetBIOSComputer    string
	DomainName         string
	ForestName         string
	FQDN               string
	NetBIOSDomain      string
	Workgroup          string
	SystemTime         string
	AuthDomain         string
}

func discoverSMBOS(host string, port int, s1 *smb1NegotiateResult, s2 *smb2NegotiateResult) *smbOSDiscovery {
	out := &smbOSDiscovery{}

	if s1 != nil {
		out.OS = cleanSMBString(s1.NativeOS)
		out.LanManager = cleanSMBString(s1.NativeLM)
		if !looksLikeOSString(out.OS) {
			out.OS = ""
		}
		if !looksLikeOSString(out.LanManager) {
			out.LanManager = ""
		}
	}

	if sess := probeSMB1SessionOS(host, port); sess != nil {
		if out.OS == "" {
			out.OS = cleanSMBString(sess.NativeOS)
		}
		if out.LanManager == "" {
			out.LanManager = cleanSMBString(sess.NativeLM)
		}
		if !looksLikeOSString(out.OS) {
			out.OS = ""
		}
		if !looksLikeOSString(out.LanManager) {
			out.LanManager = ""
		}
		if sess.SystemTime != "" {
			out.SystemTime = sess.SystemTime
		}
		if sess.Server != "" {
			out.NetBIOSComputer = cleanSMBString(sess.Server)
			out.ComputerName = cleanSMBString(sess.Server)
		}
		if sess.Domain != "" {
			out.NetBIOSDomain = cleanSMBString(sess.Domain)
		}
	}

	if nt := probeNTLMTargetInfo(host, port); nt != nil {
		if out.NetBIOSComputer == "" {
			out.NetBIOSComputer = cleanSMBString(nt.nbComputer)
		}
		if out.NetBIOSDomain == "" {
			out.NetBIOSDomain = cleanSMBString(nt.nbDomain)
		}
		if nt.dnsComputer != "" {
			out.FQDN = cleanSMBString(nt.dnsComputer)
			if i := strings.IndexByte(out.FQDN, '.'); i > 0 {
				out.ComputerName = out.FQDN[:i]
			} else if out.ComputerName == "" {
				out.ComputerName = out.FQDN
			}
		}
		out.DomainName = cleanSMBString(nt.dnsDomain)
		out.ForestName = cleanSMBString(nt.dnsTree)
		if nt.timestamp != "" {
			out.SystemTime = nt.timestamp
		}
		if out.OS == "" && nt.osVersion != "" {
			out.OS = nt.osVersion
		}
		if out.LanManager == "" && nt.lanManager != "" {
			out.LanManager = nt.lanManager
		}
	}

	if out.SystemTime == "" && s2 != nil && !s2.SystemTimeUTC.IsZero() {
		out.SystemTime = s2.SystemTime
	}
	if clock := probeSMB1Clock(host, port); clock != "" {
		out.SystemTime = clock
	}

	if out.OS != "" {
		out.CPE = makeOSCPE(out.OS)
	}
	out.AuthDomain = resolveAuthDomain(out)

	if out.OS == "" && out.LanManager == "" && out.NetBIOSComputer == "" && out.SystemTime == "" && out.AuthDomain == "" {
		return nil
	}

	if out.FQDN != "" && out.DomainName != "" && out.FQDN != out.DomainName {
		// domain member
	} else if wg := workgroupName(out); wg != "" {
		out.Workgroup = wg
	}
	return out
}

func resolveAuthDomain(d *smbOSDiscovery) string {
	if d == nil {
		return ""
	}
	if d.NetBIOSDomain != "" && !strings.EqualFold(d.NetBIOSDomain, "WORKGROUP") {
		return d.NetBIOSDomain
	}
	if d.ComputerName != "" {
		return d.ComputerName
	}
	return cleanSMBString(d.NetBIOSComputer)
}

func workgroupName(d *smbOSDiscovery) string {
	if d.NetBIOSDomain != "" {
		return d.NetBIOSDomain
	}
	return d.Workgroup
}

func cleanSMBString(s string) string {
	return strings.TrimSpace(strings.TrimRight(s, "\x00"))
}

func looksLikeOSString(s string) bool {
	s = cleanSMBString(s)
	return strings.Contains(s, "Windows Server") ||
		strings.Contains(s, "Windows 10") ||
		strings.Contains(s, "Windows 11") ||
		strings.HasPrefix(s, "Windows ") ||
		strings.HasPrefix(s, "Samba")
}

type ntlmTarget struct {
	nbComputer  string
	nbDomain    string
	dnsComputer string
	dnsDomain   string
	dnsTree     string
	timestamp   string
	osVersion   string
	lanManager  string
}

func probeNTLMTargetInfo(host string, port int) *ntlmTarget {
	conn, ch, _, err := smb2FetchChallenge(host, port)
	if err == nil {
		conn.Close()
		return parseNTLMChallengeTarget(ch)
	}
	return nil
}

func probeNTLMOnce(host string, port int, build func() []byte, secBlob []byte) *ntlmTarget {
	conn, sessionID, _, _, err := smb2ConnectAndNegotiate(host, port, build)
	if err != nil {
		return nil
	}
	defer conn.Close()
	var preauth []byte
	chMsg, _, err := smb2RequestNTLMChallenge(conn, sessionID, 1, secBlob, &preauth)
	if err != nil {
		return nil
	}
	return parseNTLMChallengeTarget(chMsg)
}

func buildSMB2SessionSetupRequest(secBlob []byte) []byte {
	b := make([]byte, 0, 24+len(secBlob))
	b = append(b, u16(25)...)
	b = append(b, 0x00)
	b = append(b, signingEnabled)
	b = append(b, u32(0)...)
	b = append(b, u32(0)...)
	off := uint16(64 + 24)
	b = append(b, u16(off)...)
	b = append(b, u16(uint16(len(secBlob)))...)
	b = append(b, make([]byte, 8)...)
	b = append(b, secBlob...)
	return b
}

func buildNTLMNegotiate() []byte {
	const flags = 0x00088207 | 0x00080000 | 0x00800000 | 0x02000000
	m := make([]byte, 48)
	copy(m, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(m[8:12], 1)
	binary.LittleEndian.PutUint32(m[12:16], flags)
	m[32] = 10
	m[33] = 0
	binary.LittleEndian.PutUint16(m[34:36], 19041)
	m[36] = 0x0f
	return m
}

func wrapSPNEGONTLMNegotiate(ntlm []byte) []byte {
	spnegoOID := []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	ntlmOID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	mechTypes := asn1BER(0xa0, asn1BER(0x30, asn1BER(0x06, ntlmOID)))
	negTokenInit := asn1BER(0x30, append(mechTypes, asn1BER(0xa0, asn1BER(0x04, ntlm))...))
	negToken := asn1BER(0xa0, negTokenInit)
	inner := append(asn1BER(0x06, spnegoOID), negToken...)
	return asn1BER(0x60, inner)
}

func asn1BER(tag byte, data []byte) []byte {
	out := []byte{tag}
	n := len(data)
	switch {
	case n <= 0x7f:
		out = append(out, byte(n))
	case n <= 0xff:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, data...)
}

func findNTLMMessage(blob []byte, msgType uint32) []byte {
	for i := 0; i+12 <= len(blob); i++ {
		if string(blob[i:i+8]) != "NTLMSSP\x00" {
			continue
		}
		if binary.LittleEndian.Uint32(blob[i+8:i+12]) == msgType {
			return blob[i:]
		}
	}
	return nil
}

func ntlmTargetFromSessionResponse(sessResp []byte) *ntlmTarget {
	off := smb2Offset(sessResp)
	if off < 0 {
		return nil
	}
	p := sessResp[off:]
	st := binary.LittleEndian.Uint32(p[8:12])
	if st != stSuccess && st != stMoreProcessing {
		return nil
	}
	sec := smb2SecurityBuffer(sessResp, 4)
	if len(sec) == 0 {
		return nil
	}
	challenge := findNTLMMessage(sec, 2)
	if challenge == nil {
		return nil
	}
	return parseNTLMChallengeTarget(challenge)
}

func parseNTLMChallengeTarget(msg []byte) *ntlmTarget {
	if len(msg) < 48 {
		return nil
	}
	infoLen := int(binary.LittleEndian.Uint16(msg[40:42]))
	infoOff := int(binary.LittleEndian.Uint32(msg[44:48]))
	var t *ntlmTarget
	if infoLen > 0 && infoOff > 0 && infoOff+infoLen <= len(msg) {
		t = parseAvPairs(msg[infoOff : infoOff+infoLen])
	}
	if t == nil {
		t = &ntlmTarget{}
	}
	if t.nbComputer == "" {
		t.nbComputer = readNTLMString(msg, 12)
	}
	if t.nbDomain == "" {
		t.nbDomain = readNTLMString(msg, 20)
	}
	if t.nbComputer == "" && t.dnsComputer == "" {
		if t.osVersion == "" {
			return nil
		}
	}
	t.osVersion, t.lanManager = ntlmVersionStrings(msg)
	return t
}

func ntlmVersionStrings(msg []byte) (osName, lanManager string) {
	if len(msg) < 56 {
		return "", ""
	}
	flags := binary.LittleEndian.Uint32(msg[20:24])
	if flags&0x02000000 == 0 {
		return "", ""
	}
	major, minor := msg[48], msg[49]
	build := binary.LittleEndian.Uint16(msg[50:52])
	return windowsBuildToOS(major, minor, build)
}

func windowsBuildToOS(major, minor byte, build uint16) (osName, lanManager string) {
	lanManager = fmt.Sprintf("Windows Server %d.%d", major, minor)
	if major == 10 && minor == 0 {
		switch build {
		case 20348:
			osName = "Windows Server 2022 Standard 20348"
			lanManager = "Windows Server 2022 Standard 6.3"
		case 17763:
			osName = "Windows Server 2019 Standard 17763"
			lanManager = "Windows Server 2019 Standard 6.3"
		case 14393:
			osName = "Windows Server 2016 Standard 14393"
			lanManager = "Windows Server 2016 Standard 6.3"
		case 9600:
			osName = "Windows Server 2012 R2 Standard 9600"
			lanManager = "Windows Server 2012 R2 6.3"
		default:
			osName = fmt.Sprintf("Windows Server %d.%d build %d", major, minor, build)
			lanManager = fmt.Sprintf("Windows Server %d.%d", major, minor)
		}
		return osName, lanManager
	}
	osName = fmt.Sprintf("Windows %d.%d.%d", major, minor, build)
	return osName, lanManager
}

func readNTLMString(msg []byte, fieldOff int) string {
	if fieldOff+8 > len(msg) {
		return ""
	}
	l := int(binary.LittleEndian.Uint16(msg[fieldOff : fieldOff+2]))
	off := int(binary.LittleEndian.Uint32(msg[fieldOff+4 : fieldOff+8]))
	if l == 0 || off+l > len(msg) {
		return ""
	}
	return cleanSMBString(decodeAVString(msg[off : off+l]))
}

func parseAvPairs(raw []byte) *ntlmTarget {
	t := &ntlmTarget{}
	for off := 0; off+4 <= len(raw); {
		id := binary.LittleEndian.Uint16(raw[off : off+2])
		l := int(binary.LittleEndian.Uint16(raw[off+2 : off+4]))
		off += 4
		if id == 0 {
			break
		}
		if off+l > len(raw) {
			break
		}
		val := raw[off : off+l]
		off += l
		switch id {
		case 1:
			t.nbComputer = cleanSMBString(decodeAVString(val))
		case 2:
			t.nbDomain = cleanSMBString(decodeAVString(val))
		case 3:
			t.dnsComputer = cleanSMBString(decodeAVString(val))
		case 4:
			t.dnsDomain = cleanSMBString(decodeAVString(val))
		case 5:
			t.dnsTree = cleanSMBString(decodeAVString(val))
		case 7:
			if len(val) >= 8 {
				ft := binary.LittleEndian.Uint64(val[:8])
				if s := filetimeToRFC3339(ft); s != "" {
					t.timestamp = s
				}
			}
		}
	}
	return t
}

func decodeAVString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if len(b)%2 == 0 {
		return decodeUTF16LE(b)
	}
	return string(b)
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

func makeOSCPE(os string) string {
	os = strings.TrimSpace(os)
	switch {
	case strings.HasPrefix(os, "Windows 5.0"):
		return "cpe:/o:microsoft:windows_2000::-"
	case strings.HasPrefix(os, "Windows 5.1"):
		return "cpe:/o:microsoft:windows_xp::-"
	case strings.Contains(os, "Server") && strings.Contains(os, "2003"):
		return "cpe:/o:microsoft:windows_server_2003::-"
	case strings.HasPrefix(os, "Windows Vista"):
		return "cpe:/o:microsoft:windows_vista::-"
	case strings.Contains(os, "Server") && strings.Contains(os, "2008"):
		return "cpe:/o:microsoft:windows_server_2008::-"
	case strings.HasPrefix(os, "Windows 7"):
		return "cpe:/o:microsoft:windows_7::-"
	case strings.HasPrefix(os, "Windows 8.1"):
		return "cpe:/o:microsoft:windows_8.1::-"
	case strings.HasPrefix(os, "Windows 8"):
		return "cpe:/o:microsoft:windows_8::-"
	case strings.HasPrefix(os, "Windows 10"):
		return "cpe:/o:microsoft:windows_10::-"
	case strings.Contains(os, "Server") && strings.Contains(os, "2022"):
		return "cpe:/o:microsoft:windows_server_2022::-"
	case strings.Contains(os, "Server") && strings.Contains(os, "2019"):
		return "cpe:/o:microsoft:windows_server_2019::-"
	case strings.Contains(os, "Server") && strings.Contains(os, "2016"):
		return "cpe:/o:microsoft:windows_server_2016::-"
	case strings.Contains(os, "Server") && strings.Contains(os, "2012"):
		return "cpe:/o:microsoft:windows_server_2012::-"
	}
	return ""
}

func windowsDisplayName(os string) string {
	if strings.HasPrefix(os, "Windows 5.0") {
		return "Windows 2000"
	}
	if strings.HasPrefix(os, "Windows 5.1") {
		return "Windows XP"
	}
	return os
}

func formatOSDiscoveryLine(d *smbOSDiscovery) string {
	if d.OS != "" && d.LanManager != "" {
		return fmt.Sprintf("%s (%s)", windowsDisplayName(d.OS), d.LanManager)
	}
	if d.OS != "" {
		return windowsDisplayName(d.OS)
	}
	if d.LanManager != "" {
		return d.LanManager
	}
	return "Unknown"
}
