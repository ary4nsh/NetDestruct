package snmp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"strings"
)

const (
	v3FlagNoAuthNoPriv = 0x00
	v3FlagAuthNoPriv   = 0x01
	v3FlagAuthPriv     = 0x03
	v3FlagReportable   = 0x04

	v3PDUSDiscoveryGet = 0xa0 // RFC 3414 engine discovery (GetRequest [0])
	v3PDUSGetRequest   = 0xa1 // SNMPv3 GetRequest-PDU [1] IMPLICIT
	v3PDUSGetResponse  = 0xa2
	v3PDUSSetRequest   = 0xa3 // SNMPv3 SetRequest-PDU [3] IMPLICIT
	v3PDUSReport       = 0xa8
	v3ScopedPDUTag     = 0xa0 // [0] IMPLICIT SEQUENCE — RFC 3412 ScopedPDU

	v3ErrAuthorization = 16 // SNMPv2/v3 authorizationError (pcap: snmpadmin → errStatus 0x10)
	v3ErrNoAccess      = 6

	oidUsmUnknownUsers          = "1.3.6.1.6.3.15.1.1.3"
	oidUsmUnsupportedSecLevels  = "1.3.6.1.6.3.15.1.1.1"
	oidUsmNotInTimeWindows      = "1.3.6.1.6.3.15.1.1.4"
)

type v3AuthProto int

const (
	v3AuthNone v3AuthProto = iota
	v3AuthMD5
	v3AuthSHA
	v3AuthSHA224
	v3AuthSHA256
	v3AuthSHA384
	v3AuthSHA512
)

type v3PrivProto int

const (
	v3PrivNone v3PrivProto = iota
	v3PrivDES
	v3PrivAES
	v3PrivAES192
	v3PrivAES256
)

type v3USM struct {
	engineID   []byte
	engineBoot uint32
	engineTime uint32
	user       string
	authProto  v3AuthProto
	privProto  v3PrivProto
	authPass   string
	privPass   string
	secretKey  []byte
	privKey    []byte
	authParams []byte
	privParams []byte
	desSalt    uint32
	aesSalt    uint64
}

type v3ProbeOutcome int

const (
	v3OutcomeFail v3ProbeOutcome = iota
	v3OutcomeOK
	v3OutcomeUnknownUser
	v3OutcomeUserExists
)

func v3AuthParamLen(p v3AuthProto) int {
	switch p {
	case v3AuthMD5, v3AuthSHA:
		return 12
	case v3AuthSHA224:
		return 16
	case v3AuthSHA256:
		return 24
	case v3AuthSHA384:
		return 32
	case v3AuthSHA512:
		return 48
	default:
		return 0
	}
}

func v3AuthPlaceholder(p v3AuthProto) []byte {
	n := v3AuthParamLen(p)
	if n == 0 {
		return []byte{0x04, 0x00}
	}
	out := make([]byte, 2+n)
	out[0] = 0x04
	out[1] = byte(n)
	return out
}

func v3HashForAuth(p v3AuthProto) hash.Hash {
	switch p {
	case v3AuthMD5:
		return md5.New()
	case v3AuthSHA:
		return sha1.New()
	case v3AuthSHA224:
		return sha256.New224()
	case v3AuthSHA256:
		return sha256.New()
	case v3AuthSHA384:
		return sha512.New384()
	case v3AuthSHA512:
		return sha512.New()
	default:
		return nil
	}
}

func v3HashPassword(h hash.Hash, password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("empty password")
	}
	pi := 0
	pw := []byte(password)
	for i := 0; i < 1048576; i += 64 {
		chunk := make([]byte, 64)
		for e := 0; e < 64; e++ {
			chunk[e] = pw[pi%len(pw)]
			pi++
		}
		if _, err := h.Write(chunk); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

func v3LocalizedKey(p v3AuthProto, password, engineID string) ([]byte, error) {
	h := v3HashForAuth(p)
	if h == nil {
		return nil, fmt.Errorf("unsupported auth protocol")
	}
	hashed, err := v3HashPassword(h, password)
	if err != nil {
		return nil, err
	}
	local := v3HashForAuth(p)
	if _, err := local.Write(hashed); err != nil {
		return nil, err
	}
	if _, err := local.Write([]byte(engineID)); err != nil {
		return nil, err
	}
	if _, err := local.Write(hashed); err != nil {
		return nil, err
	}
	return local.Sum(nil), nil
}

func v3ExtendKeyReeder(p v3AuthProto, password, engineID string) ([]byte, error) {
	key, err := v3LocalizedKey(p, password, engineID)
	if err != nil {
		return nil, err
	}
	key2, err := v3LocalizedKey(p, string(key), engineID)
	if err != nil {
		return nil, err
	}
	return append(key, key2...), nil
}

func v3PrivKey(auth v3AuthProto, priv v3PrivProto, password, engineID string) ([]byte, error) {
	var keyLen int
	switch priv {
	case v3PrivDES, v3PrivAES:
		keyLen = 16
	case v3PrivAES192:
		keyLen = 24
	case v3PrivAES256:
		keyLen = 32
	default:
		return nil, fmt.Errorf("unsupported privacy protocol")
	}
	var raw []byte
	var err error
	switch priv {
	case v3PrivAES, v3PrivAES192, v3PrivAES256:
		raw, err = v3ExtendKeyReeder(auth, password, engineID)
	default:
		raw, err = v3LocalizedKey(auth, password, engineID)
	}
	if err != nil {
		return nil, err
	}
	if len(raw) < keyLen {
		return nil, fmt.Errorf("privacy key too short")
	}
	return raw[:keyLen], nil
}

func (u *v3USM) nextPrivSalt() {
	switch u.privProto {
	case v3PrivAES, v3PrivAES192, v3PrivAES256:
		u.aesSalt++
		salt := make([]byte, 8)
		binary.BigEndian.PutUint64(salt, u.aesSalt)
		u.privParams = salt
	default:
		u.desSalt++
		salt := make([]byte, 8)
		binary.BigEndian.PutUint32(salt, u.engineBoot)
		binary.BigEndian.PutUint32(salt[4:], u.desSalt)
		u.privParams = salt
	}
}

func v3DigestRFC3414(p v3AuthProto, packet, authKey []byte) ([]byte, error) {
	var extkey [64]byte
	copy(extkey[:], authKey)
	var k1, k2 [64]byte
	for i := 0; i < 64; i++ {
		k1[i] = extkey[i] ^ 0x36
		k2[i] = extkey[i] ^ 0x5c
	}
	var h1, h2 hash.Hash
	switch p {
	case v3AuthMD5:
		h1, h2 = md5.New(), md5.New()
	case v3AuthSHA:
		h1, h2 = sha1.New(), sha1.New()
	default:
		return nil, fmt.Errorf("digestRFC3414: bad protocol")
	}
	h1.Write(k1[:])
	h1.Write(packet)
	d1 := h1.Sum(nil)
	h2.Write(k2[:])
	h2.Write(d1)
	return h2.Sum(nil)[:12], nil
}

func v3DigestRFC7860(p v3AuthProto, packet, authKey []byte) ([]byte, error) {
	var newHash func() hash.Hash
	switch p {
	case v3AuthSHA224:
		newHash = sha256.New224
	case v3AuthSHA256:
		newHash = sha256.New
	case v3AuthSHA384:
		newHash = sha512.New384
	case v3AuthSHA512:
		newHash = sha512.New
	default:
		return nil, fmt.Errorf("digestRFC7860: bad protocol")
	}
	mac := hmac.New(newHash, authKey)
	mac.Write(packet)
	return mac.Sum(nil), nil
}

func v3PacketDigest(p v3AuthProto, packet, authKey []byte) ([]byte, error) {
	switch p {
	case v3AuthMD5, v3AuthSHA:
		return v3DigestRFC3414(p, packet, authKey)
	case v3AuthSHA224, v3AuthSHA256, v3AuthSHA384, v3AuthSHA512:
		d, err := v3DigestRFC7860(p, packet, authKey)
		if err != nil {
			return nil, err
		}
		return d[:v3AuthParamLen(p)], nil
	default:
		return nil, fmt.Errorf("unsupported auth for digest")
	}
}

func (u *v3USM) marshalSecParams(flags byte) []byte {
	var body []byte
	body = append(body, asn1OctetString(u.engineID)...)
	body = append(body, asn1Uint32(u.engineBoot)...)
	body = append(body, asn1Uint32(u.engineTime)...)
	body = append(body, asn1OctetString([]byte(u.user))...)
	if flags&v3FlagAuthNoPriv != 0 {
		body = append(body, v3AuthPlaceholder(u.authProto)...)
	} else {
		body = append(body, 0x04, 0x00)
	}
	if (flags & v3FlagAuthPriv) == v3FlagAuthPriv {
		body = append(body, asn1OctetString(u.privParams)...)
	} else {
		body = append(body, 0x04, 0x00)
	}
	return asn1Seq(body)
}

func asn1Uint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return asn1TLV(0x02, b)
}

func buildV3GetPacket(msgID, reqID int, flags byte, usm *v3USM, getPDU []byte) ([]byte, error) {
	_ = reqID
	return buildV3Packet(msgID, flags, usm, getPDU)
}

func buildV3Packet(msgID int, flags byte, usm *v3USM, pdu []byte) ([]byte, error) {
	if usm.privProto > v3PrivNone {
		usm.nextPrivSalt()
	}
	scopedBody := append(append(asn1OctetString(usm.engineID), asn1OctetString(nil)...), pdu...)
	// pcap uses universal SEQUENCE (0x30), not [0] IMPLICIT 0xa0.
	scoped := asn1Seq(scopedBody)

	var msgData []byte
	if (flags & v3FlagAuthPriv) == v3FlagAuthPriv {
		enc, err := usm.encryptScoped(scoped)
		if err != nil {
			return nil, err
		}
		msgData = enc
	} else {
		msgData = scoped
	}

	globalData := asn1Seq(append(append(append(asn1Uint32(uint32(msgID)), asn1Uint32(65507)...),
		asn1OctetString([]byte{msgFlags(flags)})...), asn1Int(3)...))

	secParams := usm.marshalSecParams(msgFlags(flags))
	msg := append(append(append(asn1Int(3), globalData...), asn1OctetString(secParams)...), msgData...)
	packet := asn1Seq(msg)

	if flags&v3FlagAuthNoPriv != 0 {
		placeholder := v3AuthPlaceholder(usm.authProto)
		idx := findSubslice(packet, placeholder)
		if idx < 0 {
			return nil, fmt.Errorf("auth placeholder not found")
		}
		digest, err := v3PacketDigest(usm.authProto, packet, usm.secretKey)
		if err != nil {
			return nil, err
		}
		copy(packet[idx+2:idx+2+len(digest)], digest)
	}
	return packet, nil
}

// v3VarBind is an OID + pre-encoded ASN.1 value for SET PDUs.
type v3VarBind struct {
	OID   []int
	Value []byte
}

func buildSetPDU(reqID int, binds []v3VarBind) []byte {
	var list []byte
	for _, b := range binds {
		list = append(list, asn1Seq(append(encodeOID(b.OID), b.Value...))...)
	}
	varBindList := asn1Seq(list)
	pduBody := append(append(append(asn1Int(reqID), asn1Int(0)...), asn1Int(0)...), varBindList...)
	return asn1TLV(v3PDUSSetRequest, pduBody)
}

func asn1IPAddress(ip net.IP) []byte {
	v4 := ip.To4()
	if v4 == nil {
		return asn1TLV(0x40, make([]byte, 4))
	}
	return asn1TLV(0x40, []byte(v4))
}

func msgFlags(flags byte) byte {
	return flags | v3FlagReportable
}

func findSubslice(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		if bytesEqual(b[i:i+len(sub)], sub) {
			return i
		}
	}
	return -1
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (u *v3USM) encryptScoped(scoped []byte) ([]byte, error) {
	switch u.privProto {
	case v3PrivAES, v3PrivAES192, v3PrivAES256:
		var iv [16]byte
		binary.BigEndian.PutUint32(iv[:], u.engineBoot)
		binary.BigEndian.PutUint32(iv[4:], u.engineTime)
		copy(iv[8:], u.privParams)
		block, err := aes.NewCipher(u.privKey)
		if err != nil {
			return nil, err
		}
		stream := cipher.NewCFBEncrypter(block, iv[:])
		out := make([]byte, len(scoped))
		stream.XORKeyStream(out, scoped)
		return asn1OctetString(out), nil
	case v3PrivDES:
		preiv := u.privKey[8:]
		var iv [8]byte
		for i := range iv {
			iv[i] = preiv[i] ^ u.privParams[i]
		}
		block, err := des.NewCipher(u.privKey[:8])
		if err != nil {
			return nil, err
		}
		pad := des.BlockSize - len(scoped)%des.BlockSize
		if pad == des.BlockSize {
			pad = 0
		}
		padded := append(append([]byte{}, scoped...), make([]byte, pad)...)
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(out, padded)
		return asn1OctetString(out), nil
	default:
		return nil, fmt.Errorf("unsupported privacy protocol")
	}
}

func (u *v3USM) decryptScoped(packet []byte, i int) ([]byte, int, error) {
	if readByte(packet, &i) != 0x04 {
		return nil, 0, fmt.Errorf("expected encrypted octet string")
	}
	ct, ok := readOctets(packet, &i)
	if !ok {
		return nil, 0, fmt.Errorf("invalid ciphertext")
	}
	switch u.privProto {
	case v3PrivAES, v3PrivAES192, v3PrivAES256:
		var iv [16]byte
		binary.BigEndian.PutUint32(iv[:], u.engineBoot)
		binary.BigEndian.PutUint32(iv[4:], u.engineTime)
		copy(iv[8:], u.privParams)
		block, err := aes.NewCipher(u.privKey)
		if err != nil {
			return nil, 0, err
		}
		out := make([]byte, len(ct))
		cipher.NewCFBDecrypter(block, iv[:]).XORKeyStream(out, ct)
		return out, 0, nil
	case v3PrivDES:
		preiv := u.privKey[8:]
		var iv [8]byte
		for j := range iv {
			iv[j] = preiv[j] ^ u.privParams[j]
		}
		block, err := des.NewCipher(u.privKey[:8])
		if err != nil {
			return nil, 0, err
		}
		out := make([]byte, len(ct))
		cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(out, ct)
		return out, 0, nil
	default:
		return nil, 0, fmt.Errorf("unsupported privacy protocol")
	}
}

type v3Parsed struct {
	outcome    v3ProbeOutcome
	sysDescr   string
	engineID   []byte
	engineBoot uint32
	engineTime uint32
	reportOID  string
	errStatus  int
}

func buildGetPDU(reqID int, oid []int) []byte {
	nullValue := []byte{0x05, 0x00}
	varBind := asn1Seq(append(encodeOID(oid), nullValue...))
	varBindList := asn1Seq(varBind)
	pduBody := append(append(append(asn1Int(reqID), asn1Int(0)...), asn1Int(0)...), varBindList...)
	return asn1TLV(v3PDUSGetRequest, pduBody)
}

func v3AuthByName(name string) v3AuthProto {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "MD5":
		return v3AuthMD5
	case "SHA":
		return v3AuthSHA
	case "SHA-224":
		return v3AuthSHA224
	case "SHA-256":
		return v3AuthSHA256
	case "SHA-384":
		return v3AuthSHA384
	case "SHA-512":
		return v3AuthSHA512
	default:
		return v3AuthNone
	}
}

func v3PrivByName(name string) v3PrivProto {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "DES":
		return v3PrivDES
	case "AES":
		return v3PrivAES
	case "AES-192":
		return v3PrivAES192
	case "AES-256":
		return v3PrivAES256
	default:
		return v3PrivNone
	}
}

func parseV3Packet(b []byte, usm *v3USM) (*v3Parsed, error) {
	i := 0
	if readByte(b, &i) != 0x30 {
		return nil, fmt.Errorf("invalid snmp packet")
	}
	if _, ok := readLength(b, &i); !ok {
		return nil, fmt.Errorf("invalid length")
	}
	if readByte(b, &i) != 0x02 {
		return nil, fmt.Errorf("missing version")
	}
	ver, ok := readInt(b, &i)
	if !ok || ver != 3 {
		return nil, fmt.Errorf("not snmp v3")
	}

	if readByte(b, &i) != 0x30 {
		return nil, fmt.Errorf("missing global data")
	}
	if _, ok := readLength(b, &i); !ok {
		return nil, fmt.Errorf("bad global data length")
	}
	if readByte(b, &i) != 0x02 {
		return nil, fmt.Errorf("missing msg id")
	}
	if _, ok := readInt(b, &i); !ok {
		return nil, fmt.Errorf("bad msg id")
	}
	for skip := 0; skip < 3; skip++ {
		tag := readByte(b, &i)
		if tag == 0x02 {
			if _, ok := readInt(b, &i); !ok {
				return nil, fmt.Errorf("bad int field")
			}
		} else if tag == 0x04 {
			if _, ok := readOctets(b, &i); !ok {
				return nil, fmt.Errorf("bad octet field")
			}
		} else {
			return nil, fmt.Errorf("unexpected tag 0x%02x", tag)
		}
	}

	if readByte(b, &i) != 0x04 {
		return nil, fmt.Errorf("missing security parameters")
	}
	secRaw, ok := readOctets(b, &i)
	if !ok {
		return nil, fmt.Errorf("bad security parameters")
	}
	engineID, boots, engineTime, privParams := parseUSMParams(secRaw)
	if usm != nil && len(privParams) > 0 {
		usm.privParams = privParams
	}

	if i >= len(b) {
		return &v3Parsed{engineID: engineID, engineBoot: boots, engineTime: engineTime}, nil
	}

	tag := b[i]
	var scoped []byte
	switch {
	case tag == 0x04 && usm != nil && usm.privProto > v3PrivNone:
		dec, _, err := usm.decryptScoped(b, i)
		if err != nil {
			return &v3Parsed{engineID: engineID, engineBoot: boots, engineTime: engineTime}, nil
		}
		scoped = dec
	case tag == v3ScopedPDUTag, tag == 0x30:
		if readByte(b, &i) != tag {
			return nil, fmt.Errorf("bad scoped pdu tag")
		}
		scopeLen, ok := readLength(b, &i)
		if !ok {
			return nil, fmt.Errorf("bad scoped length")
		}
		scopeEnd := i + scopeLen
		if scopeEnd > len(b) {
			return nil, fmt.Errorf("truncated scoped pdu")
		}
		scoped = b[i:scopeEnd]
	default:
		return &v3Parsed{engineID: engineID, engineBoot: boots, engineTime: engineTime}, nil
	}

	si := 0
	if readByte(scoped, &si) != 0x30 {
		// scoped may start with sequence wrapper already stripped
		si = 0
	} else {
		if _, ok := readLength(scoped, &si); !ok {
			return nil, fmt.Errorf("bad inner scoped length")
		}
	}
	if readByte(scoped, &si) != 0x04 {
		return &v3Parsed{engineID: engineID, engineBoot: boots, engineTime: engineTime}, nil
	}
	if _, ok := readOctets(scoped, &si); !ok {
		return nil, fmt.Errorf("bad context engine id")
	}
	if readByte(scoped, &si) != 0x04 {
		return nil, fmt.Errorf("bad context name tag")
	}
	if _, ok := readOctets(scoped, &si); !ok {
		return nil, fmt.Errorf("bad context name")
	}

	pduTag := readByte(scoped, &si)
	pduLen, ok := readLength(scoped, &si)
	if !ok {
		return nil, fmt.Errorf("bad pdu length")
	}
	pduEnd := si + pduLen
	if pduEnd > len(scoped) {
		return nil, fmt.Errorf("truncated pdu")
	}
	pdu := scoped[si:pduEnd]

	out := &v3Parsed{engineID: engineID, engineBoot: boots, engineTime: engineTime}
	switch pduTag {
	case v3PDUSGetResponse:
		out.outcome, out.sysDescr, out.errStatus = parseV3ResponsePDU(pdu)
	case v3PDUSReport:
		out.reportOID = parseV3ReportPDU(pdu)
		out.outcome = v3ReportOutcome(out.reportOID)
	default:
		out.outcome = v3OutcomeFail
	}
	return out, nil
}

// v3ReportOutcome maps snmpUsmStats Report OIDs to user-enum results.
// unknownUserNames => reject; unsupportedSecurityLevels/notInTimeWindow => user exists (RFC 3414 USM).
func v3ReportOutcome(reportOID string) v3ProbeOutcome {
	oid := strings.TrimPrefix(reportOID, ".")
	switch {
	case strings.HasPrefix(oid, oidUsmUnknownUsers):
		return v3OutcomeUnknownUser
	case strings.HasPrefix(oid, oidUsmUnsupportedSecLevels):
		return v3OutcomeUserExists
	case strings.HasPrefix(oid, oidUsmNotInTimeWindows):
		return v3OutcomeUserExists
	default:
		return v3OutcomeFail
	}
}

func parseUSMParams(b []byte) ([]byte, uint32, uint32, []byte) {
	i := 0
	if readByte(b, &i) != 0x30 {
		return nil, 0, 0, nil
	}
	scopeLen, ok := readLength(b, &i)
	if !ok {
		return nil, 0, 0, nil
	}
	end := i + scopeLen

	readOctet := func() []byte {
		if i >= end || readByte(b, &i) != 0x04 {
			return nil
		}
		v, _ := readOctets(b, &i)
		return v
	}
	readIntField := func() uint32 {
		if i >= end || readByte(b, &i) != 0x02 {
			return 0
		}
		v, _ := readInt(b, &i)
		return uint32(v)
	}

	engineID := readOctet()
	boots := readIntField()
	engineTime := readIntField()
	_ = readOctet() // username
	_ = readOctet() // auth params
	privParams := readOctet()
	return engineID, boots, engineTime, privParams
}

func parseV3ResponsePDU(pdu []byte) (v3ProbeOutcome, string, int) {
	i := 0
	if readByte(pdu, &i) != 0x02 {
		return v3OutcomeFail, "", 0
	}
	if _, ok := readInt(pdu, &i); !ok {
		return v3OutcomeFail, "", 0
	}
	if readByte(pdu, &i) != 0x02 {
		return v3OutcomeFail, "", 0
	}
	errStatus, ok := readInt(pdu, &i)
	if !ok {
		return v3OutcomeFail, "", 0
	}
	if readByte(pdu, &i) != 0x02 {
		return v3OutcomeFail, "", errStatus
	}
	if _, ok := readInt(pdu, &i); !ok {
		return v3OutcomeFail, "", errStatus
	}
	if errStatus == v3ErrAuthorization || errStatus == v3ErrNoAccess || errStatus == 4 {
		return v3OutcomeUserExists, "", errStatus
	}
	if errStatus != 0 {
		return v3OutcomeFail, "", errStatus
	}
	if readByte(pdu, &i) != 0x30 {
		return v3OutcomeOK, "", 0
	}
	if _, ok := readLength(pdu, &i); !ok {
		return v3OutcomeOK, "", 0
	}
	if readByte(pdu, &i) != 0x30 {
		return v3OutcomeOK, "", 0
	}
	if _, ok := readLength(pdu, &i); !ok {
		return v3OutcomeOK, "", 0
	}
	if readByte(pdu, &i) != 0x06 {
		return v3OutcomeOK, "", 0
	}
	if _, ok := readOctets(pdu, &i); !ok {
		return v3OutcomeOK, "", 0
	}
	if readByte(pdu, &i) != 0x04 {
		return v3OutcomeOK, "", 0
	}
	val, ok := readOctets(pdu, &i)
	if !ok {
		return v3OutcomeOK, "", 0
	}
	return v3OutcomeOK, strings.TrimSpace(string(val)), 0
}

func parseV3ReportPDU(pdu []byte) string {
	i := 0
	if readByte(pdu, &i) != 0x02 {
		return ""
	}
	if _, ok := readInt(pdu, &i); !ok {
		return ""
	}
	for skip := 0; skip < 2; skip++ {
		if readByte(pdu, &i) != 0x02 {
			return ""
		}
		if _, ok := readInt(pdu, &i); !ok {
			return ""
		}
	}
	if readByte(pdu, &i) != 0x30 {
		return ""
	}
	if _, ok := readLength(pdu, &i); !ok {
		return ""
	}
	if readByte(pdu, &i) != 0x30 {
		return ""
	}
	if _, ok := readLength(pdu, &i); !ok {
		return ""
	}
	if readByte(pdu, &i) != 0x06 {
		return ""
	}
	oidRaw, ok := readOctets(pdu, &i)
	if !ok {
		return ""
	}
	oid, err := decodeOID(oidRaw)
	if err != nil {
		return ""
	}
	return formatOID(oid)
}
