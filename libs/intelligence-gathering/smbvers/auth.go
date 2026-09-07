package smbvers

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"time"
)

const (
	ntStatusLogonFailure        = 0xC000006D
	ntStatusAccountLockedOut    = 0xC0000234
	ntStatusAccountDisabled     = 0xC0000072
	ntStatusPasswordMustChange  = 0xC0000224
	ntStatusInvalidLogonHours   = 0xC000006F
	ntStatusInvalidWorkstation  = 0xC0000070
	ntStatusAccountExpired      = 0xC0000193
	ntStatusLogonTypeNotGranted = 0xC000015B
)

// LoginOutcome classifies an SMB session-setup authentication attempt.
type LoginOutcome int

const (
	LoginFail LoginOutcome = iota
	LoginSuccess
	LoginGuest
	LoginNotGranted
	LoginDisabled
	LoginExpired
	LoginChangePassword
	LoginInvalidLogonHours
	LoginInvalidWorkstation
	LoginAccountLocked
	LoginAccountLockedNow
)

func (o LoginOutcome) Message() string {
	switch o {
	case LoginSuccess:
		return "Valid credentials"
	case LoginGuest:
		return "Valid credentials, account granted guest access only"
	case LoginNotGranted:
		return "Valid credentials, but account wasn't allowed to log in (often happens with blank passwords)"
	case LoginDisabled:
		return "Valid credentials, account disabled"
	case LoginExpired:
		return "Valid credentials, account expired"
	case LoginChangePassword:
		return "Valid credentials, password must be changed at next logon"
	case LoginInvalidLogonHours:
		return "Valid credentials, account cannot log in at current time"
	case LoginInvalidWorkstation:
		return "Valid credentials, account cannot log in from current host"
	case LoginAccountLocked:
		return "Valid credentials, account locked (hopefully not by us!)"
	case LoginAccountLockedNow:
		return "Valid credentials, account just became locked (oops!)"
	default:
		return "Invalid credentials"
	}
}

func (o LoginOutcome) ValidPassword() bool {
	switch o {
	case LoginSuccess, LoginGuest, LoginNotGranted, LoginDisabled, LoginExpired,
		LoginChangePassword, LoginInvalidLogonHours, LoginInvalidWorkstation, LoginAccountLocked,
		LoginAccountLockedNow:
		return true
	default:
		return false
	}
}

// TryLogin performs SMB2 NTLM session setup with the given credentials.
func TryLogin(host string, port int, user, pass, domain string) (LoginOutcome, error) {
	out, _, err := TryLoginWithStatus(host, port, user, pass, domain)
	return out, err
}

// TryLoginWithStatus returns the mapped login outcome and raw SMB status code.
func TryLoginWithStatus(host string, port int, user, pass, domain string) (LoginOutcome, uint32, error) {
	if port <= 0 {
		port = portDirect
	}

	conn, chMsg, sessionID, err := smb2FetchChallenge(host, port)
	if err != nil {
		out, err := tryLoginSMB1(host, port, user, pass, domain)
		if err != nil {
			return LoginFail, ntStatusLogonFailure, err
		}
		if out == LoginSuccess || out == LoginGuest {
			return out, stSuccess, nil
		}
		return out, ntStatusLogonFailure, nil
	}
	defer conn.Close()

	dom := loginDomainForNTLM(chMsg, domain)
	auth, _ := buildNTLMv2Authenticate(chMsg, user, pass, dom)
	hdr := smb2RequestHeader(smb2CmdSessionSetup, 2)
	putU64(hdr[40:48], sessionID)
	if err := netbiosWrite(conn, append(hdr, buildSMB2SessionSetupRequest(auth)...)); err != nil {
		return LoginFail, 0xffffffff, err
	}
	authResp, err := netbiosRead(conn)
	if err != nil {
		return LoginFail, 0xffffffff, err
	}
	st := smb2Status(authResp)
	if st == stSuccess && smb2SessionFlags(authResp)&0x0001 != 0 {
		return LoginGuest, st, nil
	}
	return mapLoginStatus(st), st, nil
}

func smb2Status(pkt []byte) uint32 {
	off := smb2Offset(pkt)
	if off < 0 || len(pkt) < off+12 {
		return 0xffffffff
	}
	return binary.LittleEndian.Uint32(pkt[off+8 : off+12])
}

func smb2SessionID(pkt []byte) uint64 {
	off := smb2Offset(pkt)
	if off < 0 || len(pkt) < off+48 {
		return 0
	}
	return binary.LittleEndian.Uint64(pkt[off+40 : off+48])
}

func ntlmChallengeFromSession(pkt []byte) ([]byte, uint64, error) {
	return extractNTLMChallenge(pkt)
}

func wrapSPNEGONTLMAuth(ntlm []byte) []byte {
	spnegoOID := []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	ntlmOID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	// NegTokenResp: negState=accept-incomplete (1), supportedMech=NTLM, responseToken=NTLMSSP_AUTH
	state := asn1BER(0xa0, asn1BER(0x0a, []byte{0x01}))
	mech := asn1BER(0xa1, asn1BER(0x06, ntlmOID))
	token := asn1BER(0xa2, asn1BER(0x04, ntlm))
	negToken := asn1BER(0x30, append(append(state, mech...), token...))
	negTokenResp := asn1BER(0xa1, negToken)
	inner := append(asn1BER(0x06, spnegoOID), negTokenResp...)
	return asn1BER(0x60, inner)
}

func loginDomainForNTLM(challenge []byte, domain string) string {
	if domain != "" {
		return domain
	}
	if t := parseNTLMChallengeTarget(challenge); t != nil && t.nbDomain != "" {
		return t.nbDomain
	}
	return ""
}

func mapLoginStatus(st uint32) LoginOutcome {
	switch st {
	case stSuccess:
		return LoginSuccess
	case ntStatusLogonFailure:
		return LoginFail
	case ntStatusAccountLockedOut:
		return LoginAccountLocked
	case ntStatusAccountDisabled:
		return LoginDisabled
	case ntStatusPasswordMustChange:
		return LoginChangePassword
	case ntStatusInvalidLogonHours:
		return LoginInvalidLogonHours
	case ntStatusInvalidWorkstation:
		return LoginInvalidWorkstation
	case ntStatusAccountExpired:
		return LoginExpired
	case ntStatusLogonTypeNotGranted:
		return LoginNotGranted
	default:
		return LoginFail
	}
}

func buildNTLMv2Authenticate(challengeMsg []byte, user, pass, domain string) ([]byte, []byte) {
	if len(challengeMsg) < 32 {
		return nil, nil
	}
	var serverChallenge [8]byte
	copy(serverChallenge[:], challengeMsg[24:32])
	targetInfo := ntlmTargetInfoBytes(challengeMsg)
	v2Hash := ntowfv2(pass, user, domain)
	ntResp := computeNTLMv2Response(serverChallenge, targetInfo, user, pass, domain)
	sessionKey := ntlmv2SessionBaseKey(v2Hash, ntResp)

	domainU := utf16LE(domain)
	userU := utf16LE(user)
	workU := utf16LE("")
	lm := make([]byte, 24)

	payload := append(domainU, userU...)
	payload = append(payload, workU...)
	payload = append(payload, lm...)
	payload = append(payload, ntResp...)

	const base = 64
	domainOff := base
	userOff := domainOff + len(domainU)
	workOff := userOff + len(userU)
	lmOff := workOff + len(workU)
	ntOff := lmOff + len(lm)

	m := make([]byte, base+len(payload))
	copy(m, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(m[8:12], 3)
	writeNTLMField(m, 12, lm, lmOff)
	writeNTLMField(m, 20, ntResp, ntOff)
	writeNTLMField(m, 28, domainU, domainOff)
	writeNTLMField(m, 36, userU, userOff)
	writeNTLMField(m, 44, workU, workOff)
	writeNTLMField(m, 52, nil, 0)

	flags := uint32(0x00088205)
	if len(challengeMsg) >= 24 {
		cf := binary.LittleEndian.Uint32(challengeMsg[20:24])
		flags = (cf & 0xe088a005) | 0x00088205
	}
	binary.LittleEndian.PutUint32(m[60:64], flags)
	copy(m[base:], payload)
	return m, sessionKey
}

func ntlmv2SessionBaseKey(v2Hash, ntResp []byte) []byte {
	if len(ntResp) < 16 {
		return nil
	}
	mac := hmac.New(md5.New, v2Hash)
	mac.Write(ntResp[:16])
	return mac.Sum(nil)
}

func writeNTLMField(m []byte, fieldOff int, data []byte, absOff int) {
	binary.LittleEndian.PutUint16(m[fieldOff:fieldOff+2], uint16(len(data)))
	binary.LittleEndian.PutUint16(m[fieldOff+2:fieldOff+4], uint16(len(data)))
	binary.LittleEndian.PutUint32(m[fieldOff+4:fieldOff+8], uint32(absOff))
}

func ntlmTargetInfoBytes(msg []byte) []byte {
	if len(msg) < 48 {
		return nil
	}
	infoLen := int(binary.LittleEndian.Uint16(msg[40:42]))
	infoOff := int(binary.LittleEndian.Uint32(msg[44:48]))
	if infoLen <= 0 || infoOff <= 0 || infoOff+infoLen > len(msg) {
		return nil
	}
	return msg[infoOff : infoOff+infoLen]
}

func computeNTLMv2Response(serverChallenge [8]byte, targetInfo []byte, user, pass, domain string) []byte {
	v2Hash := ntowfv2(pass, user, domain)
	clientChallenge := randBytes(8)
	blob := buildNTLMv2Blob(targetInfo, clientChallenge)
	mac := hmac.New(md5.New, v2Hash)
	mac.Write(serverChallenge[:])
	mac.Write(blob)
	proof := mac.Sum(nil)[:16]
	return append(proof, blob...)
}

func buildNTLMv2Blob(targetInfo, clientChallenge []byte) []byte {
	b := make([]byte, 0, 28+len(targetInfo)+4)
	b = append(b, 0x01, 0x01, 0x00, 0x00)
	b = append(b, 0x00, 0x00, 0x00, 0x00)
	ft := uint64(time.Now().UnixNano()/100) + 116444736000000000
	tmp := make([]byte, 8)
	binary.LittleEndian.PutUint64(tmp, ft)
	b = append(b, tmp...)
	b = append(b, clientChallenge...)
	b = append(b, 0, 0, 0, 0)
	b = append(b, targetInfo...)
	b = append(b, 0, 0, 0, 0)
	return b
}

func ntowfv2(password, user, domain string) []byte {
	h := md4New()
	h.Write(utf16LE(password))
	ntHash := h.Sum(nil)
	identity := utf16LE(stringToUpper(user) + domain)
	mac := hmac.New(md5.New, ntHash)
	mac.Write(identity)
	return mac.Sum(nil)
}

func stringToUpper(s string) string {
	r := []rune(s)
	for i := range r {
		if r[i] >= 'a' && r[i] <= 'z' {
			r[i] -= 'a' - 'A'
		}
	}
	return string(r)
}
