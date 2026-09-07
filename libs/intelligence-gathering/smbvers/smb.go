package smbvers

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	portDirect = 445
	portNBSS   = 139

	smb2CmdNegotiate    = 0x0000
	smb2CmdSessionSetup = 0x0001

	stSuccess        = 0x00000000
	stMoreProcessing = 0xC0000016

	signingEnabled  = 0x01
	signingRequired = 0x02

	capDFS            = 0x00000001
	capLeasing        = 0x00000002
	capLargeMTU       = 0x00000004
	capMultiChannel   = 0x00000008
	capPersistent     = 0x00000010
	capDirectoryLease = 0x00000020
	capEncryption     = 0x00000040

	ctxPreauth      = 0x0001
	ctxEncryption   = 0x0002
	ctxCompression  = 0x0003
	ctxSigning      = 0x0008

	hashSHA512       = 0x0001
	cipherAES128CCM  = 0x0001
	cipherAES128GCM  = 0x0002
	cipherAES256CCM  = 0x0003
	cipherAES256GCM  = 0x0004
	signHMACSHA256   = 0x0000
	signAESCMC       = 0x0001
	signAESGMAC      = 0x0002
	compLZNT1        = 0x0001
	compLZ77         = 0x0002
	compLZ77Huff     = 0x0003
	compPatternV1    = 0x0004
)

var dialectNames = map[uint16]string{
	0x0202: "SMB 2.0.2",
	0x0210: "SMB 2.1",
	0x0300: "SMB 3.0",
	0x0302: "SMB 3.0.2",
	0x0311: "SMB 3.1.1",
	0x02FF: "SMB 2.???",
}

func dialectLabel(d uint16) string {
	if s, ok := dialectNames[d]; ok {
		return s
	}
	return fmt.Sprintf("0x%04x", d)
}

func smb2VersionsFromDialect(d uint16) []int {
	switch {
	case d >= 0x0300:
		return []int{2, 3}
	case d >= 0x0202:
		return []int{2}
	default:
		return nil
	}
}

func smb2Offset(pkt []byte) int {
	if len(pkt) >= 8 && pkt[4] == 0xfe {
		return 4
	}
	if len(pkt) >= 4 && pkt[0] == 0xfe {
		return 0
	}
	return -1
}

func smb2RequestHeader(cmd uint16, msgID uint64) []byte {
	h := make([]byte, 64)
	copy(h[0:4], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(h[4:6], 64)
	binary.LittleEndian.PutUint16(h[12:14], cmd)
	binary.LittleEndian.PutUint16(h[14:16], 1)
	binary.LittleEndian.PutUint64(h[24:32], msgID)
	copy(h[32:36], []byte{0xff, 0xfe, 0x00, 0x00})
	return h
}

func writeNegotiateContext(w []byte, ctxType uint16, data []byte) []byte {
	out := append(w, u16(ctxType)...)
	out = append(out, u16(uint16(len(data)))...)
	out = append(out, 0, 0, 0, 0)
	out = append(out, data...)
	return out
}

func pad8(n int) []byte {
	p := (8 - (n % 8)) % 8
	if p == 0 {
		return nil
	}
	b := make([]byte, p)
	for i := range b {
		b[i] = 0xff
	}
	return b
}

// buildSMB2Negotiate311 — MS-SMB2 / 3.1.1 negotiate with contexts.
func buildSMB2Negotiate311() []byte {
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}
	return buildSMB2NegotiateWithDialects(dialects, true)
}

func buildSMB2NegotiateLegacy() []byte {
	dialects := []uint16{0x0210, 0x0202}
	return buildSMB2NegotiateWithDialects(dialects, false)
}

// buildSMB2Negotiate202 (SMB 2.0.2 only, no extra caps).
func buildSMB2Negotiate202() []byte {
	body := make([]byte, 0, 38)
	body = append(body, u16(36)...)
	body = append(body, u16(1)...)
	body = append(body, signingEnabled, 0x00)
	body = append(body, 0x00, 0x00)
	body = append(body, u32(0)...)
	body = append(body, randBytes(16)...)
	body = append(body, make([]byte, 8)...)
	body = append(body, u16(0x0202)...)
	return append(smb2RequestHeader(smb2CmdNegotiate, 0), body...)
}

func buildSMB2NegotiateWithDialects(dialects []uint16, with311Contexts bool) []byte {
	body := make([]byte, 0, 512)
	body = append(body, u16(36)...)
	body = append(body, u16(uint16(len(dialects)))...)
	body = append(body, signingEnabled, 0x00) // SecurityMode
	body = append(body, 0x00, 0x00)           // Reserved
	if with311Contexts {
		body = append(body, u32(capEncryption)...)
	} else {
		body = append(body, u32(0)...)
	}
	body = append(body, randBytes(16)...)

	if !with311Contexts {
		body = append(body, make([]byte, 8)...)
		for _, d := range dialects {
			body = append(body, u16(d)...)
		}
		hdr := smb2RequestHeader(smb2CmdNegotiate, 0)
		return append(hdr, body...)
	}

	const ctxFieldOff = 28
	body = append(body, make([]byte, 8)...)
	for _, d := range dialects {
		body = append(body, u16(d)...)
	}
	body = append(body, 0xff, 0xff)

	salt := randBytes(32)
	preauth := append(u16(1), u16(32)...)
	preauth = append(preauth, u16(hashSHA512)...)
	preauth = append(preauth, salt...)

	enc := append(u16(4), u16(cipherAES128CCM)...)
	enc = append(enc, u16(cipherAES128GCM)...)
	enc = append(enc, u16(cipherAES256CCM)...)
	enc = append(enc, u16(cipherAES256GCM)...)

	comp := append(u16(4), 0, 0)
	comp = append(comp, u32(0)...)
	comp = append(comp, u16(compLZNT1)...)
	comp = append(comp, u16(compLZ77)...)
	comp = append(comp, u16(compLZ77Huff)...)
	comp = append(comp, u16(compPatternV1)...)

	sign := append(u16(3), u16(signHMACSHA256)...)
	sign = append(sign, u16(signAESCMC)...)
	sign = append(sign, u16(signAESGMAC)...)

	ctx := writeNegotiateContext(nil, ctxPreauth, preauth)
	ctx = append(ctx, pad8(len(preauth))...)
	ctx = writeNegotiateContext(ctx, ctxEncryption, enc)
	ctx = append(ctx, pad8(len(enc))...)
	ctx = writeNegotiateContext(ctx, ctxSigning, sign)
	ctx = append(ctx, pad8(len(sign))...)
	ctx = writeNegotiateContext(ctx, ctxCompression, comp)

	ctxAbsOff := uint32(64 + len(body))
	binary.LittleEndian.PutUint32(body[ctxFieldOff:ctxFieldOff+4], ctxAbsOff)
	binary.LittleEndian.PutUint16(body[ctxFieldOff+4:ctxFieldOff+6], 4)

	body = append(body, ctx...)

	hdr := smb2RequestHeader(smb2CmdNegotiate, 0)
	return append(hdr, body...)
}

type smb2NegotiateResult struct {
	Dialect              uint16
	DialectName          string
	SigningRequired      bool
	SigningEnabled       bool
	ServerGUID           string
	Versions             []int
	CompressionAlgos     []string
	EncryptionAlgos      []string
	SigningAlgos         []string
	PreauthHashAlgs      []string
	PreauthSaltHex       string
	ServerCapabilities   uint32
	MaxReadSize          uint32
	MaxWriteSize         uint32
	SystemTime           string
	SystemTimeUTC        time.Time
	AuthDomain           string
	OSVersion            string
}

func parseSMB2NegotiateResponse(pkt []byte) (*smb2NegotiateResult, error) {
	off := smb2Offset(pkt)
	if off < 0 || len(pkt) < off+64+8 {
		return nil, fmt.Errorf("short smb2 packet")
	}
	p := pkt[off:]
	if p[0] != 0xfe {
		return nil, fmt.Errorf("not smb2")
	}
	status := binary.LittleEndian.Uint32(p[8:12])
	if status != stSuccess {
		return nil, fmt.Errorf("status 0x%08x", status)
	}
	cmd := binary.LittleEndian.Uint16(p[12:14])
	if cmd != smb2CmdNegotiate {
		return nil, fmt.Errorf("unexpected command 0x%04x", cmd)
	}
	body := p[64:]
	if len(body) < 6 {
		return nil, fmt.Errorf("short negotiate body")
	}
	secMode := body[2]
	dialect := binary.LittleEndian.Uint16(body[4:6])
	ctxCount := binary.LittleEndian.Uint16(body[6:8])
	guid := body[8:24]
	res := &smb2NegotiateResult{
		Dialect:         dialect,
		DialectName:     dialectLabel(dialect),
		SigningEnabled:  secMode&signingEnabled != 0,
		SigningRequired: secMode&signingRequired != 0,
		ServerGUID:      formatGUID(guid),
		Versions:        smb2VersionsFromDialect(dialect),
	}
	if len(body) >= 28 {
		res.ServerCapabilities = binary.LittleEndian.Uint32(body[24:28])
	}
	if len(body) >= 40 {
		res.MaxReadSize = binary.LittleEndian.Uint32(body[32:36])
		res.MaxWriteSize = binary.LittleEndian.Uint32(body[36:40])
	}
	if len(body) >= 48 {
		ft := binary.LittleEndian.Uint64(body[40:48])
		res.SystemTime = filetimeToRFC3339(ft)
		res.SystemTimeUTC = time.Unix(int64(ft/10000000)-11644473600, 0).UTC()
	}
	if dialect >= 0x0311 && ctxCount > 0 && len(body) >= 64 {
		ctxOff := int(binary.LittleEndian.Uint32(body[60:64]))
		start := off + ctxOff
		if ctxOff >= 64 && start < len(pkt) {
			parseNegotiateContexts(pkt[start:], ctxCount, res)
		}
	}
	return res, nil
}

func parseNegotiateContexts(data []byte, count uint16, res *smb2NegotiateResult) {
	off := 0
	for i := 0; i < int(count) && off+8 <= len(data); i++ {
		typ := binary.LittleEndian.Uint16(data[off : off+2])
		l := int(binary.LittleEndian.Uint16(data[off+2 : off+4]))
		off += 8
		if l < 0 || off+l > len(data) {
			break
		}
		val := data[off : off+l]
		off += l
		if rem := off % 8; rem != 0 {
			off += 8 - rem
		}
		switch typ {
		case ctxPreauth:
			algs, salt := parsePreauthContext(val)
			res.PreauthHashAlgs = append(res.PreauthHashAlgs, algs...)
			if salt != "" {
				res.PreauthSaltHex = salt
			}
		case ctxEncryption:
			res.EncryptionAlgos = appendUniqueStrings(res.EncryptionAlgos, parseCipherList(val)...)
		case ctxSigning:
			res.SigningAlgos = appendUniqueStrings(res.SigningAlgos, parseSigningContext(val)...)
		case ctxCompression:
			res.CompressionAlgos = appendUniqueStrings(res.CompressionAlgos, parseCompressionList(val)...)
		}
	}
}

func parsePreauthContext(raw []byte) (hashAlgs []string, saltHex string) {
	if len(raw) < 4 {
		return nil, ""
	}
	hashCount := int(binary.LittleEndian.Uint16(raw[0:2]))
	saltLen := int(binary.LittleEndian.Uint16(raw[2:4]))
	pos := 4
	for i := 0; i < hashCount && pos+2 <= len(raw); i++ {
		h := binary.LittleEndian.Uint16(raw[pos : pos+2])
		pos += 2
		hashAlgs = append(hashAlgs, hashAlgorithmName(h))
	}
	if saltLen > 0 && pos+saltLen <= len(raw) {
		saltHex = hex.EncodeToString(raw[pos : pos+saltLen])
	}
	return hashAlgs, saltHex
}

func hashAlgorithmName(id uint16) string {
	switch id {
	case hashSHA512:
		return "SHA-512"
	default:
		return fmt.Sprintf("0x%04x", id)
	}
}

func parseSigningContext(raw []byte) []string {
	if len(raw) < 2 {
		return nil
	}
	n := int(binary.LittleEndian.Uint16(raw[0:2]))
	var out []string
	for i := 0; i < n && 2+i*2+2 <= len(raw); i++ {
		out = append(out, signingAlgName(binary.LittleEndian.Uint16(raw[2+i*2 : 4+i*2])))
	}
	return out
}

func signingAlgName(id uint16) string {
	switch id {
	case signHMACSHA256:
		return "HMAC-SHA256"
	case signAESCMC:
		return "AES-CMAC"
	case signAESGMAC:
		return "AES-GMAC"
	default:
		return fmt.Sprintf("0x%04x", id)
	}
}

func parseCipherList(raw []byte) []string {
	if len(raw) < 2 {
		return nil
	}
	n := int(binary.LittleEndian.Uint16(raw[0:2]))
	var out []string
	for i := 0; i < n && 2+i*2+2 <= len(raw); i++ {
		out = append(out, cipherName(binary.LittleEndian.Uint16(raw[2+i*2:4+i*2])))
	}
	return out
}

func cipherName(c uint16) string {
	switch c {
	case cipherAES128CCM:
		return "AES-128-CCM"
	case cipherAES128GCM:
		return "AES-128-GCM"
	case cipherAES256CCM:
		return "AES-256-CCM"
	case cipherAES256GCM:
		return "AES-256-GCM"
	default:
		return fmt.Sprintf("0x%04x", c)
	}
}

func parseCompressionList(raw []byte) []string {
	if len(raw) < 8 {
		return nil
	}
	n := int(binary.LittleEndian.Uint16(raw[0:2]))
	var out []string
	base := 8
	for i := 0; i < n && base+2 <= len(raw); i++ {
		out = append(out, compressionName(binary.LittleEndian.Uint16(raw[base : base+2])))
		base += 2
	}
	return out
}

func compressionName(c uint16) string {
	switch c {
	case compLZNT1:
		return "LZNT1"
	case compLZ77:
		return "LZ77"
	case compLZ77Huff:
		return "LZ77+Huffman"
	case compPatternV1:
		return "Pattern_V1"
	case 0x0000:
		return "None"
	default:
		return fmt.Sprintf("0x%04x", c)
	}
}

func appendUniqueStrings(base []string, extra ...string) []string {
	seen := make(map[string]bool, len(base))
	for _, s := range base {
		seen[s] = true
	}
	for _, s := range extra {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		base = append(base, s)
	}
	return base
}

func formatGUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		binary.LittleEndian.Uint16(b[8:10]),
		b[10:16])
}

func buildSMB2NegotiateSingle(dialect uint16) func() []byte {
	return func() []byte {
		if dialect == 0x0311 {
			return buildSMB2NegotiateWithDialects([]uint16{dialect}, true)
		}
		return buildSMB2NegotiateWithDialects([]uint16{dialect}, false)
	}
}

func buildSMB1NegotiateNTLM012() []byte {
	dialects := []byte{0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0}
	h := make([]byte, 35+len(dialects))
	copy(h[0:4], []byte{0xff, 'S', 'M', 'B'})
	h[4] = 0x72
	h[32] = 0
	binary.LittleEndian.PutUint16(h[33:35], uint16(len(dialects)))
	copy(h[35:], dialects)
	return h
}

func smb2SecurityBuffer(pkt []byte, bodyField int) []byte {
	off := smb2Offset(pkt)
	if off < 0 || len(pkt) < off+64+bodyField+4 {
		return nil
	}
	body := pkt[off+64:]
	bufOff := int(binary.LittleEndian.Uint16(body[bodyField : bodyField+2]))
	length := int(binary.LittleEndian.Uint16(body[bodyField+2 : bodyField+4]))
	start := off + bufOff
	if bufOff < 64 || length <= 0 || start+length > len(pkt) {
		return nil
	}
	out := make([]byte, length)
	copy(out, pkt[start:start+length])
	return out
}

func smbDialectLabel(d uint16) string {
	switch d {
	case 0x0202:
		return "2.0.2"
	case 0x0210:
		return "2.1"
	case 0x0300:
		return "3.0"
	case 0x0302:
		return "3.0.2"
	case 0x0311:
		return "3.1.1"
	default:
		return fmt.Sprintf("0x%04x", d)
	}
}

func filetimeToRFC3339(ft uint64) string {
	if ft == 0 {
		return ""
	}
	const epoch = 11644473600
	sec := int64(ft/10000000) - epoch
	if sec < 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05Z")
}

func buildSMB1NegotiateRequest() []byte {
	dialects := []byte{
		0x02, 'P', 'C', ' ', 'N', 'E', 'T', 'W', 'O', 'R', 'K', ' ', 'P', 'R', 'O', 'G', 'R', 'A', 'M', ' ', '1', '.', '0', 0,
		0x02, 'L', 'A', 'N', 'M', 'A', 'N', '1', '.', '0', 0,
		0x02, 'L', 'M', '1', '.', '2', 'X', '0', '0', '2', 0,
		0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0,
	}
	h := make([]byte, 35+len(dialects))
	copy(h[0:4], []byte{0xff, 'S', 'M', 'B'})
	h[4] = 0x72
	h[32] = 0
	binary.LittleEndian.PutUint16(h[33:35], uint16(len(dialects)))
	copy(h[35:], dialects)
	return h
}

type smb1NegotiateResult struct {
	NativeOS string
	NativeLM string
}

func parseSMB1NegotiateResponse(pkt []byte) (*smb1NegotiateResult, error) {
	if len(pkt) < 36 || pkt[0] != 0xff || pkt[4] != 0x72 {
		return nil, fmt.Errorf("not smb1 negotiate response")
	}
	wc := int(pkt[32])
	if wc < 1 {
		return nil, fmt.Errorf("invalid word count")
	}
	off := 33 + wc*2
	if off+2 > len(pkt) {
		return nil, fmt.Errorf("short smb1 response")
	}
	bc := int(binary.LittleEndian.Uint16(pkt[off : off+2]))
	off += 2
	if bc <= 0 || off+bc > len(pkt) {
		return nil, fmt.Errorf("invalid byte count")
	}
	data := pkt[off : off+bc]
	unicode := binary.LittleEndian.Uint16(pkt[10:12])&0x8000 != 0
	strs := smb1DataStrings(data, unicode)
	res := &smb1NegotiateResult{}
	if len(strs) > 0 {
		res.NativeOS = strings.TrimSpace(strs[0])
	}
	if len(strs) > 1 {
		res.NativeLM = strings.TrimSpace(strs[1])
	}
	return res, nil
}

func smb1DataStrings(data []byte, unicode bool) []string {
	if len(data) == 0 {
		return nil
	}
	if unicode {
		return splitUTF16NullTerminated(data)
	}
	payload := data
	if len(payload) > 0 && payload[0] == 0 {
		payload = payload[1:]
	}
	return strings.Split(string(payload), "\x00")
}

func splitUTF16NullTerminated(b []byte) []string {
	if len(b)%2 == 1 {
		b = b[:len(b)-1]
	}
	var out []string
	var cur []uint16
	for i := 0; i+1 < len(b); i += 2 {
		r := binary.LittleEndian.Uint16(b[i : i+2])
		if r == 0 {
			if len(cur) > 0 {
				out = append(out, string(utf16.Decode(cur)))
				cur = cur[:0]
			}
			continue
		}
		cur = append(cur, r)
	}
	if len(cur) > 0 {
		out = append(out, string(utf16.Decode(cur)))
	}
	return out
}

func u16(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
