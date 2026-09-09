package credsniff

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"
)

const tag = "\x1b[96m[CRED]\x1b[0m"

type rawSocket interface {
	Recv([]byte) (int, error)
	Close() error
}

// Sniffer captures credentials from live traffic, a single pcap, or a directory of pcaps.
type Sniffer struct {
	Interface string
	IgnoreIP  string
	PcapFile  string
	PcapDir   string
	OutputDir string
}

// ─── output writer with deduplication ────────────────────────────────────────

type outputWriter struct {
	dir  string
	seen map[string]bool
}

var out *outputWriter

func initWriter(dir string) {
	out = &outputWriter{dir: dir, seen: make(map[string]bool)}
	if dir != "" {
		os.MkdirAll(dir, 0755)
	}
}

func (w *outputWriter) write(filename, data, key string) {
	if w == nil || w.dir == "" {
		return
	}
	dk := filename + "\x00" + key
	if w.seen[dk] {
		return
	}
	w.seen[dk] = true
	path := filepath.Join(w.dir, filename)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(data + "\n")
}

// ─── per-flow / per-file state ────────────────────────────────────────────────

var (
	frags     = make(map[string]map[uint32][]byte) // srcIPPort→ack→payload (TCP reassembly)
	flowUser  = make(map[string]string)            // srcIPPort → username (FTP/SMTP/IRC flow pairing)
	flowNick  = make(map[string]string)            // srcIPPort → IRC nick
	smtpStep  = make(map[string]int)               // srcIPPort → AUTH LOGIN step (1=sent_user)
	ntlmChals = make(map[string]string)            // bidir flow key → hex challenge
	mailAuths = make(map[string]bool)              // srcIPPort → pending base64 continuation
)

// resetState clears per-file flow state but keeps the output writer's dedup cache.
func resetState() {
	frags = make(map[string]map[uint32][]byte)
	flowUser = make(map[string]string)
	flowNick = make(map[string]string)
	smtpStep = make(map[string]int)
	ntlmChals = make(map[string]string)
	mailAuths = make(map[string]bool)
}

// biFlowKey produces the same key regardless of packet direction.
// The side with the higher port number comes first.
func biFlowKey(srcIP, dstIP string, srcPort, dstPort uint16) string {
	if srcPort > dstPort {
		return fmt.Sprintf("%s:%d|%s:%d", srcIP, srcPort, dstIP, dstPort)
	}
	return fmt.Sprintf("%s:%d|%s:%d", dstIP, dstPort, srcIP, srcPort)
}

// ─── Run ──────────────────────────────────────────────────────────────────────

func (s *Sniffer) Run() error {
	initWriter(s.OutputDir)

	switch {
	case s.PcapFile != "":
		return readPcap(s.PcapFile, s.IgnoreIP)
	case s.PcapDir != "":
		return readPcapDir(s.PcapDir, s.IgnoreIP)
	}

	iface, err := net.InterfaceByName(s.Interface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", s.Interface, err)
	}
	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	fmt.Printf("%s sniffing on %s", tag, s.Interface)
	if s.IgnoreIP != "" {
		fmt.Printf(" (ignoring %s)", s.IgnoreIP)
	}
	fmt.Println(" — Ctrl+C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		sock.Close()
		os.Exit(0)
	}()

	buf := make([]byte, 65536)
	for {
		n, err := sock.Recv(buf)
		if err != nil {
			return nil
		}
		parsePacket(buf[:n], s.IgnoreIP)
	}
}

// ─── Ethernet / IP dispatcher ─────────────────────────────────────────────────

func parsePacket(raw []byte, ignoreIP string) {
	if len(raw) < 14 {
		return
	}
	if uint16(raw[12])<<8|uint16(raw[13]) != 0x0800 {
		return // IPv4 only
	}
	ip := raw[14:]
	if len(ip) < 20 {
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if len(ip) < ihl+8 {
		return
	}
	srcIP := fmt.Sprintf("%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15])
	dstIP := fmt.Sprintf("%d.%d.%d.%d", ip[16], ip[17], ip[18], ip[19])
	if ignoreIP != "" && (srcIP == ignoreIP || dstIP == ignoreIP) {
		return
	}
	l4 := ip[ihl:]
	proto := ip[9]

	switch proto {
	case 6: // TCP
		if len(l4) < 20 {
			return
		}
		srcPort := uint16(l4[0])<<8 | uint16(l4[1])
		dstPort := uint16(l4[2])<<8 | uint16(l4[3])
		seq := uint32(l4[4])<<24 | uint32(l4[5])<<16 | uint32(l4[6])<<8 | uint32(l4[7])
		ack := uint32(l4[8])<<24 | uint32(l4[9])<<16 | uint32(l4[10])<<8 | uint32(l4[11])
		hdrLen := int(l4[12]>>4) * 4
		if len(l4) <= hdrLen {
			return
		}
		payload := l4[hdrLen:]
		parseTCP(srcIP, dstIP, srcPort, dstPort, payload, seq, ack)

	case 17: // UDP
		if len(l4) < 8 || len(l4) == 8 {
			return
		}
		srcPort := uint16(l4[0])<<8 | uint16(l4[1])
		dstPort := uint16(l4[2])<<8 | uint16(l4[3])
		payload := l4[8:]
		parseUDP(srcIP, dstIP, srcPort, dstPort, payload)
	}
}

// ─── TCP ──────────────────────────────────────────────────────────────────────

func parseTCP(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, seq, ack uint32) {
	src := fmt.Sprintf("%s:%d", srcIP, srcPort)
	dst := fmt.Sprintf("%s:%d", dstIP, dstPort)

	// Fragment reassembly
	if len(frags) > 50 {
		for k := range frags {
			delete(frags, k)
			break
		}
	}
	m, ok := frags[src]
	if !ok {
		m = make(map[uint32][]byte)
		frags[src] = m
	}
	combined := append(append([]byte(nil), m[ack]...), payload...)
	if len(combined) > 5000 {
		combined = combined[len(combined)-200:]
	}
	m[ack] = combined

	// Run all protocol parsers. Each checks port/content and returns early if not applicable.
	// Parsers that need only the current packet use `payload`; those needing reassembled flow use `combined`.
	parseFTP(src, dst, dstPort, payload)
	parseSMTP(src, dst, dstPort, payload)
	parseIRCFTP(src, dst, srcPort, dstPort, payload)
	parseTelnet(src, dst, string(payload))
	parseLDAP(src, dst, dstPort, payload)
	parseMSSQL(src, dst, dstPort, payload)
	parseKerberosTCP(src, dst, dstPort, payload)
	parseHTTPAndNTLM(srcIP, dstIP, srcPort, dstPort, src, dst, combined, ack, seq)
}

// ─── UDP ──────────────────────────────────────────────────────────────────────

func parseUDP(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) {
	src := fmt.Sprintf("%s:%d", srcIP, srcPort)
	dst := fmt.Sprintf("%s:%d", dstIP, dstPort)
	if dstPort == 88 || srcPort == 88 {
		parseKerberosUDP(src, dst, payload)
	}
	if dstPort == 161 || dstPort == 162 || srcPort == 161 || srcPort == 162 {
		parseSNMP(src, dst, payload)
	}
}

// ─── FTP ──────────────────────────────────────────────────────────────────────

func parseFTP(src, dst string, dstPort uint16, payload []byte) {
	// Only if dport is 21 or the flow already has a tracked FTP user
	isFTP := dstPort == 21
	if !isFTP {
		if _, tracked := flowUser[src]; !tracked {
			return
		}
	}

	for _, line := range bytes.Split(payload, []byte("\r\n")) {
		line = bytes.TrimSpace(line)
		up := bytes.ToUpper(line)
		if bytes.HasPrefix(up, []byte("USER ")) {
			user := string(bytes.TrimSpace(line[5:]))
			flowUser[src] = user
			printer(src, dst, "FTP User: "+user)
		} else if bytes.HasPrefix(up, []byte("PASS ")) {
			pwd := string(bytes.TrimSpace(line[5:]))
			if user, ok := flowUser[src]; ok {
				creds := user + ":" + pwd
				printer(src, dst, "FTP Pass: "+pwd)
				out.write("FTP-Plaintext.txt", creds, creds)
				delete(flowUser, src)
			} else {
				printer(src, dst, "FTP Pass: "+pwd)
			}
		}
	}
}

// ─── SMTP ─────────────────────────────────────────────────────────────────────

func parseSMTP(src, dst string, dstPort uint16, payload []byte) {
	if dstPort != 25 && dstPort != 587 && dstPort != 465 {
		return
	}

	for _, line := range bytes.Split(payload, []byte("\r\n")) {
		line = bytes.TrimSpace(line)
		up := bytes.ToUpper(line)

		if bytes.HasPrefix(up, []byte("AUTH PLAIN ")) {
			b64 := bytes.TrimSpace(line[11:])
			if dec, err := base64.StdEncoding.DecodeString(string(b64)); err == nil {
				parts := bytes.Split(dec, []byte("\x00"))
				if len(parts) >= 3 && len(parts[1]) > 0 && len(parts[2]) > 0 {
					user, pwd := string(parts[1]), string(parts[2])
					creds := user + ":" + pwd
					printer(src, dst, "SMTP AUTH PLAIN: "+creds)
					out.write("SMTP-Plaintext.txt", creds, creds)
				}
			}
		} else if bytes.EqualFold(line, []byte("AUTH LOGIN")) {
			smtpStep[src] = 1
		} else if step, ok := smtpStep[src]; ok && len(line) > 0 {
			if dec, err := base64.StdEncoding.DecodeString(string(line)); err == nil {
				switch step {
				case 1: // received username
					flowUser[src] = string(dec)
					smtpStep[src] = 2
				case 2: // received password
					if user, exists := flowUser[src]; exists {
						creds := user + ":" + string(dec)
						printer(src, dst, "SMTP AUTH LOGIN: "+creds)
						out.write("SMTP-Plaintext.txt", creds, creds)
						delete(flowUser, src)
					}
					delete(smtpStep, src)
				}
			}
		}
	}
}

// ─── IRC / FTP cleartext ────────────────────────────────────────────────────

func isIRCPort(port uint16) bool {
	return (port >= 6660 && port <= 6670) || port == 6697 || port == 7000
}

func parseIRCFTP(src, dst string, srcPort, dstPort uint16, payload []byte) {
	// Detect IRC by port or by NICK/JOIN keyword
	isIRC := isIRCPort(dstPort) || isIRCPort(srcPort)
	if !isIRC {
		for _, line := range bytes.Split(payload, []byte("\r\n")) {
			up := bytes.ToUpper(bytes.TrimSpace(line))
			if bytes.HasPrefix(up, []byte("NICK ")) || bytes.HasPrefix(up, []byte("JOIN ")) {
				isIRC = true
				break
			}
		}
	}

	for _, line := range bytes.Split(payload, []byte("\r\n")) {
		line = bytes.TrimSpace(line)
		up := bytes.ToUpper(line)

		if isIRC {
			if bytes.HasPrefix(up, []byte("NICK ")) {
				nick := string(bytes.TrimSpace(line[5:]))
				flowNick[src] = nick
				printer(src, dst, "IRC nick: "+nick)
			} else if bytes.HasPrefix(up, []byte("USER ")) {
				parts := bytes.Fields(line[5:])
				if len(parts) > 0 {
					flowUser[src] = string(parts[0])
				}
			} else if bytes.HasPrefix(up, []byte("PASS ")) {
				pwd := string(bytes.TrimSpace(line[5:]))
				nick := flowNick[src]
				if nick != "" {
					creds := nick + ":" + pwd
					printer(src, dst, "IRC pass: "+pwd)
					out.write("IRC-Plaintext.txt", creds, creds)
				} else {
					printer(src, dst, "IRC pass: "+pwd)
				}
			} else if bytes.Contains(bytes.ToUpper(line), []byte("NS IDENTIFY")) ||
				bytes.Contains(bytes.ToLower(line), []byte("nickserv :identify")) {
				idx := bytes.LastIndex(bytes.ToUpper(line), []byte("IDENTIFY "))
				if idx >= 0 {
					pwd := string(bytes.TrimSpace(line[idx+9:]))
					printer(src, dst, "IRC NickServ pass: "+pwd)
					if nick, ok := flowNick[src]; ok {
						out.write("IRC-Plaintext.txt", nick+":"+pwd, nick+":"+pwd)
					}
				}
			}
		} else {
			// FTP (non-port-21 fallback via content detection, handled by parseFTP)
		}
	}
}

// ─── Telnet ───────────────────────────────────────────────────────────────────

var telnetBuf = make(map[string]string)

func parseTelnet(src, dst, load string) {
	if buf, ok := telnetBuf[src]; ok {
		if utf8.ValidString(load) {
			buf += load
		}
		if strings.ContainsAny(buf, "\r\n") {
			val := strings.TrimRight(buf, "\r\n ")
			if idx := strings.Index(val, " "); idx >= 0 {
				printer(src, dst, "Telnet "+val[:idx]+": "+val[idx+1:])
			}
			delete(telnetBuf, src)
			return
		}
		telnetBuf[src] = buf
		return
	}
	low := strings.ToLower(strings.TrimRight(load, "\t \r\n"))
	switch {
	case strings.HasSuffix(low, "username:") || strings.HasSuffix(low, "login:"):
		telnetBuf[dst] = "username "
	case strings.HasSuffix(low, "password:"):
		telnetBuf[dst] = "password "
	}
}

// ─── LDAP Simple Bind ─────────────────────────────────────────────────────────

func parseLDAP(src, dst string, dstPort uint16, payload []byte) {
	if dstPort != 389 && dstPort != 636 {
		return
	}
	if len(payload) < 10 || payload[0] != 0x30 {
		return
	}

	pos := 1
	// Skip outer SEQUENCE length
	if payload[pos]&0x80 != 0 {
		pos += int(payload[pos]&0x7f) + 1
	} else {
		pos++
	}

	// Skip message ID: 0x02 + lenByte + value
	if pos+2 > len(payload) || payload[pos] != 0x02 {
		return
	}
	pos += 2 + int(payload[pos+1])

	// BindRequest tag = 0x60
	if pos >= len(payload) || payload[pos] != 0x60 {
		return
	}
	pos++
	if payload[pos]&0x80 != 0 {
		pos += int(payload[pos]&0x7f) + 1
	} else {
		pos++
	}

	// Skip LDAP version: 0x02 + lenByte + value
	if pos+2 > len(payload) || payload[pos] != 0x02 {
		return
	}
	pos += 2 + int(payload[pos+1])

	// DN: 0x04 + lenByte + DN bytes
	if pos+2 > len(payload) || payload[pos] != 0x04 {
		return
	}
	dnLen := int(payload[pos+1])
	pos += 2
	if pos+dnLen > len(payload) {
		return
	}
	dn := string(payload[pos : pos+dnLen])
	pos += dnLen

	// Simple auth: 0x80 context tag
	if pos+1 >= len(payload) || payload[pos] != 0x80 {
		return
	}
	pwdLen := int(payload[pos+1])
	pos += 2

	var pwd string
	if pwdLen == 0 {
		pwd = "(empty)"
	} else {
		if pos+pwdLen > len(payload) {
			return
		}
		pwd = string(payload[pos : pos+pwdLen])
		if !isPrintable(pwd) {
			return
		}
	}

	msg := fmt.Sprintf("LDAP Simple Bind: %s : %s", dn, pwd)
	printer(src, dst, msg)
	key := dn + ":" + pwd
	out.write("LDAP-Simple.txt", key, key)
}

// ─── MSSQL TDS Login ──────────────────────────────────────────────────────────

func parseMSSQL(src, dst string, dstPort uint16, payload []byte) {
	if dstPort != 1433 {
		return
	}
	if len(payload) < 58 || payload[0] != 0x10 || payload[1] != 0x01 {
		return
	}

	usernameOff := int(binary.LittleEndian.Uint16(payload[48:50]))
	pwdOff      := int(binary.LittleEndian.Uint16(payload[52:54]))
	appOff      := int(binary.LittleEndian.Uint16(payload[56:58]))

	if pwdOff <= usernameOff || appOff <= pwdOff {
		return
	}
	usernameLen := pwdOff - usernameOff
	pwdLen      := appOff - pwdOff

	if usernameLen <= 0 || usernameLen > 200 || pwdLen <= 0 || pwdLen > 200 {
		return
	}

	uStart := 8 + usernameOff
	pStart := 8 + pwdOff
	if uStart+usernameLen > len(payload) || pStart+pwdLen > len(payload) {
		return
	}

	username := utf16LE(payload[uStart : uStart+usernameLen])
	pwd := mssqlDecode(payload[pStart : pStart+pwdLen])

	if username == "" || pwd == "" {
		return
	}

	msg := fmt.Sprintf("MSSQL Username: %s  Password: %s", username, pwd)
	printer(src, dst, msg)
	key := username + ":" + pwd
	out.write("MSSQL-Plaintext.txt", key, key)
}

// mssqlDecode reverses the TDS password obfuscation: XOR nibble-swap then XOR 0xa5.
func mssqlDecode(data []byte) string {
	dec := make([]byte, len(data))
	for i, b := range data {
		b ^= 0xa5
		dec[i] = (b<<4)&0xf0 | (b>>4)&0x0f
	}
	return strings.TrimRight(utf16LE(dec), "\x00")
}

// ─── Kerberos AS-REQ pre-auth (etype 23) ─────────────────────────────────────

func parseKerberosTCP(src, dst string, dstPort uint16, payload []byte) {
	if dstPort != 88 {
		return
	}
	// TCP Kerberos has a 4-byte record length before the KRB message
	if len(payload) <= 4 {
		return
	}
	parseKerberosData(src, dst, payload[4:])
}

func parseKerberosUDP(src, dst string, payload []byte) {
	parseKerberosData(src, dst, payload)
}

// parseKerberosData parses a Kerberos AS-REQ at fixed offsets.
func parseKerberosData(src, dst string, data []byte) {
	if len(data) < 50 {
		return
	}
	if data[17] != 0x0a || data[39] != 0x17 { // MsgType=10 (AS-REQ preauthentication), EncType=23 (RC4-HMAC)
		return
	}

	marker40 := data[40:44]
	if bytes.Equal(marker40, []byte{0xa2, 0x36, 0x04, 0x34}) ||
		bytes.Equal(marker40, []byte{0xa2, 0x35, 0x04, 0x33}) {
		// Path A: known marker
		hashLen := int(int8(data[41]))
		if hashLen != 53 && hashLen != 54 {
			return
		}
		end := 44 + hashLen
		if end > len(data) {
			return
		}
		hash := data[44:end]
		switchHash := append(append([]byte(nil), hash[16:]...), hash[:16]...)

		nameOff := 144
		if hashLen == 53 {
			nameOff = 143
		}
		if nameOff+1 >= len(data) {
			return
		}
		nameLen := int(int8(data[nameOff]))
		if nameOff+1+nameLen > len(data) {
			return
		}
		name := data[nameOff+1 : nameOff+1+nameLen]

		domOff := nameOff + 1 + nameLen + 3
		if domOff+1 >= len(data) {
			return
		}
		domLen := int(int8(data[domOff]))
		if domOff+1+domLen > len(data) {
			return
		}
		domain := data[domOff+1 : domOff+1+domLen]
		emitKerbHash(src, dst, name, domain, switchHash)

	} else {
		// Path B: alternate structure
		if len(data) < 49 {
			return
		}
		hashLen := int(int8(data[48]))
		if hashLen <= 0 || 49+hashLen > len(data) {
			return
		}
		hash := data[49 : 49+hashLen]
		switchHash := append(append([]byte(nil), hash[16:]...), hash[:16]...)

		nameBase := hashLen + 97
		if nameBase+1 >= len(data) {
			return
		}
		nameLen := int(int8(data[nameBase]))
		if nameBase+1+nameLen > len(data) {
			return
		}
		name := data[nameBase+1 : nameBase+1+nameLen]

		domBase := nameBase + 1 + nameLen + 3
		if domBase+1 >= len(data) {
			return
		}
		domLen := int(int8(data[domBase]))
		if domBase+1+domLen > len(data) {
			return
		}
		domain := data[domBase+1 : domBase+1+domLen]
		emitKerbHash(src, dst, name, domain, switchHash)
	}
}

func emitKerbHash(src, dst string, name, domain, switchHash []byte) {
	domStr := strings.ToUpper(string(domain))
	hexHash := strings.ToUpper(fmt.Sprintf("%x", switchHash))
	hash := fmt.Sprintf("$krb5pa$23$%s$%s$dummy$%s", string(name), domStr, hexHash)
	printer(src, dst, "MS Kerberos: "+hash)
	out.write("MSKerb.txt", hash, string(name))
}

// ─── SNMP community string (v1 and v2c) ───────────────────────────────────────

func parseSNMP(src, dst string, payload []byte) {
	if len(payload) < 8 || payload[0] != 0x30 {
		return
	}

	// Determine outer length encoding
	pos := 1
	if payload[pos]&0x80 != 0 {
		pos += int(payload[pos]&0x7f) + 1
	} else {
		pos++
	}

	// Version field: INTEGER (0x02) with 1-byte length (0x01) and value 0 (v1) or 1 (v2c)
	if pos+3 > len(payload) || payload[pos] != 0x02 || payload[pos+1] != 0x01 {
		return
	}
	version := payload[pos+2]
	if version != 0 && version != 1 { // 0=v1, 1=v2c
		return
	}
	pos += 3

	// Community string: OCTET STRING (0x04)
	if pos+2 > len(payload) || payload[pos] != 0x04 {
		return
	}
	commLen := int(payload[pos+1])
	pos += 2
	if commLen == 0 || commLen > 50 || pos+commLen > len(payload) {
		return
	}
	comm := string(payload[pos : pos+commLen])
	if !isPrintable(comm) {
		return
	}

	versionStr := "SNMPv1"
	if version == 1 {
		versionStr = "SNMPv2c"
	}
	printer(src, dst, versionStr+" community string: "+comm)
	out.write(versionStr+".txt", comm, comm)
}

// ─── HTTP, Basic Auth, NTLM, password fields ──────────────────────────────────

var (
	reHTTPBasic    = regexp.MustCompile(`(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)`)
	reNTLMChal     = regexp.MustCompile(`(?i)(?:WWW|Proxy)-Authenticate:\s*NTLM\s+([A-Za-z0-9+/=]+)`)
	reNTLMAuth     = regexp.MustCompile(`(?i)(?:Authorization|Proxy-Authorization):\s*NTLM\s+([A-Za-z0-9+/=]+)`)
	rePasswordField = regexp.MustCompile(
		`(?i)(?:^|&)(password|pass|_password|passwd|session_password|sessionpassword|` +
			`login_password|loginpassword|form_pw|pw|userpassword|pwd|upassword|` +
			`passwort|passwrd|wppassword|j_password|admin_password|admin_pass|` +
			`secret|api_key|token|key|auth)\s*=\s*([^&"\s]{4,100})`)
	reNTLMSP2 = regexp.MustCompile(`(?s)NTLMSSP\x00\x02\x00\x00\x00.+`)
	reNTLMSP3 = regexp.MustCompile(`(?s)NTLMSSP\x00\x03\x00\x00\x00.+`)

	httpMethods = []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "CONNECT ", "OPTIONS ", "TRACE "}
	staticExts  = []string{".jpg", ".jpeg", ".gif", ".png", ".css", ".ico", ".js", ".svg", ".woff"}

	userFields = []string{
		"log", "login", "wpname", "ahd_username", "unickname", "nickname", "user", "user_name",
		"alias", "pseudo", "email", "username", "_username", "userid", "form_loginname",
		"loginname", "login_id", "loginid", "session_key", "sessionkey", "pop_login", "uid",
		"id", "user_id", "screename", "uname", "ulogin", "acctname", "account", "member",
		"mailaddress", "membername", "login_username", "login_email", "loginusername",
		"loginemail", "uin", "sign-in", "usuario",
	}
	reUserFields []*regexp.Regexp
	rePassFields []*regexp.Regexp
)

func init() {
	passFields := []string{
		"ahd_password", "pass", "password", "_password", "passwd", "session_password",
		"sessionpassword", "login_password", "loginpassword", "form_pw", "pw", "userpassword",
		"pwd", "upassword", "passwort", "passwrd", "wppassword", "upasswd", "senha", "contrasena",
	}
	for _, f := range userFields {
		reUserFields = append(reUserFields, regexp.MustCompile(`(?i)`+regexp.QuoteMeta(f)+`=([^&\s]{1,75})`))
	}
	for _, f := range passFields {
		rePassFields = append(rePassFields, regexp.MustCompile(`(?i)`+regexp.QuoteMeta(f)+`=([^&\s]{1,75})`))
	}
}

func parseHTTPAndNTLM(srcIP, dstIP string, srcPort, dstPort uint16, src, dst string, full []byte, ack, seq uint32) {
	payload := string(full)
	fkey := biFlowKey(srcIP, dstIP, srcPort, dstPort)

	// HTTP Basic Auth
	if m := reHTTPBasic.FindSubmatch(full); m != nil {
		if dec, err := base64.StdEncoding.DecodeString(string(m[1])); err == nil {
			creds := string(dec)
			if strings.Contains(creds, ":") {
				printer(src, dst, "HTTP Basic Auth: "+creds)
				out.write("HTTP-Basic.txt", creds, creds)
			}
		}
	}

	// NTLM via HTTP headers — challenge (server → client)
	if m := reNTLMChal.FindSubmatch(full); m != nil {
		if dec, err := base64.StdEncoding.DecodeString(string(m[1])); err == nil {
			if len(dec) >= 32 && string(dec[0:8]) == "NTLMSSP\x00" && binary.LittleEndian.Uint32(dec[8:12]) == 2 {
				challenge := strings.ToUpper(fmt.Sprintf("%x", dec[24:32]))
				ntlmChals[fkey] = challenge
			}
		}
	}

	// NTLM via HTTP headers — response (client → server)
	if m := reNTLMAuth.FindSubmatch(full); m != nil {
		if dec, err := base64.StdEncoding.DecodeString(string(m[1])); err == nil {
			extractNTLMType3(src, dst, fkey, dec)
		}
	}

	// Raw NTLM magic bytes (SMB, RPC, LDAP, etc.) anywhere in TCP stream
	if m := reNTLMSP2.Find(full); m != nil {
		if len(m) >= 32 && binary.LittleEndian.Uint32(m[8:12]) == 2 {
			challenge := strings.ToUpper(fmt.Sprintf("%x", m[24:32]))
			ntlmChals[fkey] = challenge
		}
	}
	if m := reNTLMSP3.Find(full); m != nil {
		extractNTLMType3(src, dst, fkey, m)
	}

	// HTTP password fields
	if m := rePasswordField.FindStringSubmatch(payload); m != nil {
		val := m[2]
		if len(val) > 3 && isPrintable(val) {
			line := extractLine(payload, m[0])
			printer(src, dst, "HTTP password field: "+line)
			out.write("HTTP-PasswordFields.txt", line, val)
		}
	}

	// HTTP URLs and form body
	parseHTTPContent(src, dst, payload)
}

func parseHTTPContent(src, dst, payload string) {
	httpLine, headers, body := splitHTTP(payload)
	hmap := headersToMap(headers)
	host := hmap["host"]

	if httpLine != "" {
		method, path := splitHTTPLine(httpLine)
		if method != "" {
			if url := buildURL(method, host, path); url != "" {
				printer(src, "", url)
			}
		}
		if body != "" {
			if u, p, ok := getLoginPass(body); ok {
				printer(src, dst, "HTTP username: "+u)
				printer(src, dst, "HTTP password: "+p)
			}
		}
		if strings.HasPrefix(httpLine, "POST ") && !strings.Contains(host, "ocsp.") && body != "" {
			out := body
			if len(out) > 99 {
				out = out[:99] + "..."
			}
			printer(src, "", "POST load: "+out)
		}
	}
}

// ─── NTLM type-3 parser (NETNTLMv1 / NETNTLMv2) ─────────────────────────────

func extractNTLMType3(src, dst, fkey string, msg []byte) {
	if len(msg) < 44 || string(msg[0:8]) != "NTLMSSP\x00" {
		return
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != 3 {
		return
	}

	challenge := ntlmChals[fkey]
	if challenge == "" {
		challenge = "0000000000000000"
	}

	// Field layout: 12x skip, then hhi triples (len/maxlen/offset) for each field
	lmLen    := int(binary.LittleEndian.Uint16(msg[12:14]))
	lmOff    := int(binary.LittleEndian.Uint32(msg[16:20]))
	ntLen    := int(binary.LittleEndian.Uint16(msg[20:22]))
	ntOff    := int(binary.LittleEndian.Uint32(msg[24:28]))
	domLen   := int(binary.LittleEndian.Uint16(msg[28:30]))
	domOff   := int(binary.LittleEndian.Uint32(msg[32:36]))
	userLen  := int(binary.LittleEndian.Uint16(msg[36:38]))
	userOff  := int(binary.LittleEndian.Uint32(msg[40:44]))

	inBounds := func(off, ln int) bool { return off >= 0 && ln >= 0 && off+ln <= len(msg) }
	if !inBounds(lmOff, lmLen) || !inBounds(ntOff, ntLen) ||
		!inBounds(domOff, domLen) || !inBounds(userOff, userLen) {
		return
	}

	lmHash  := strings.ToUpper(fmt.Sprintf("%x", msg[lmOff:lmOff+lmLen]))
	ntHash  := strings.ToUpper(fmt.Sprintf("%x", msg[ntOff:ntOff+ntLen]))
	domain  := utf16LE(msg[domOff : domOff+domLen])
	user    := utf16LE(msg[userOff : userOff+userLen])

	if ntLen == 24 { // NTLMv1
		hash := fmt.Sprintf("%s::%s:%s:%s:%s", user, domain, lmHash, ntHash, challenge)
		printer(src, dst, "NETNTLMv1: "+hash)
		out.write("NTLMv1.txt", hash, user+"::"+domain)
	} else if ntLen > 24 && len(ntHash) >= 32 { // NTLMv2
		hash := fmt.Sprintf("%s::%s:%s:%s:%s", user, domain, challenge, ntHash[:32], ntHash[32:])
		printer(src, dst, "NETNTLMv2: "+hash)
		out.write("NTLMv2.txt", hash, user+"::"+domain)
	}
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

func splitHTTP(load string) (httpLine string, headers []string, body string) {
	hdrPart := load
	if idx := strings.Index(load, "\r\n\r\n"); idx >= 0 {
		hdrPart = load[:idx]
		body = load[idx+4:]
	}
	lines := strings.Split(hdrPart, "\r\n")
	for _, line := range lines {
		for _, m := range httpMethods {
			if strings.HasPrefix(line, m) {
				httpLine = line
				break
			}
		}
		if httpLine != "" {
			break
		}
	}
	for _, line := range lines {
		if line != httpLine && line != "" {
			headers = append(headers, line)
		}
	}
	return
}

func headersToMap(lines []string) map[string]string {
	m := make(map[string]string)
	for _, line := range lines {
		if idx := strings.Index(line, ": "); idx >= 0 {
			m[strings.ToLower(line[:idx])] = line[idx+2:]
		}
	}
	return m
}

func splitHTTPLine(line string) (method, path string) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) >= 2 {
		method, path = parts[0], parts[1]
	}
	return
}

func buildURL(method, host, path string) string {
	var u string
	if host != "" && !strings.Contains(path, host) {
		u = method + " " + host + path
	} else {
		u = method + " " + path
	}
	low := strings.ToLower(u)
	for _, ext := range staticExts {
		if strings.HasSuffix(low, ext) {
			return ""
		}
	}
	return u
}

func getLoginPass(body string) (user, pass string, found bool) {
	for _, re := range reUserFields {
		if m := re.FindStringSubmatch(body); m != nil {
			user = urlDecode(m[1])
		}
	}
	for _, re := range rePassFields {
		if m := re.FindStringSubmatch(body); m != nil {
			pass = urlDecode(m[1])
		}
	}
	if user != "" && pass != "" && len(user) < 75 && len(pass) < 75 {
		found = true
	}
	return
}

func extractLine(full, match string) string {
	for _, line := range strings.Split(full, "\n") {
		if strings.Contains(line, match) {
			line = strings.TrimSpace(line)
			if len(line) > 500 {
				line = line[:500]
			}
			return line
		}
	}
	return match
}

// ─── output ───────────────────────────────────────────────────────────────────

func printer(src, dst, msg string) {
	if dst != "" {
		fmt.Printf("%s [%s > %s] \x1b[93m%s\x1b[0m\n", tag, src, dst, msg)
	} else {
		ip := src
		if idx := strings.LastIndex(src, ":"); idx >= 0 {
			ip = src[:idx]
		}
		fmt.Printf("%s [%s] %s\n", tag, ip, msg)
	}
}

// ─── utility ──────────────────────────────────────────────────────────────────

func utf16LE(b []byte) string {
	var s strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(uint16(b[i]) | uint16(b[i+1])<<8)
		if r != 0 {
			s.WriteRune(r)
		}
	}
	return s.String()
}

func isPrintable(s string) bool {
	for _, c := range s {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func urlDecode(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) {
			if hi, lo := hexNib(s[i+1]), hexNib(s[i+2]); hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func hexNib(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
