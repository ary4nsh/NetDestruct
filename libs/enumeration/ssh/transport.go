package ssh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"strings"
)

// Minimal SSH-2 client (stdlib only) for auth-methods listing and password
// brute force — without third-party SSH libraries.

const (
	msgDisconnect       = 1
	msgIgnore           = 2
	msgDebug            = 4
	msgServiceRequest   = 5
	msgServiceAccept    = 6
	msgExtInfo          = 7
	msgKexInit          = 20
	msgNewKeys          = 21
	msgKexECDHInit      = 30
	msgKexECDHReply     = 31
	msgUserAuthRequest  = 50
	msgUserAuthFailure  = 51
	msgUserAuthSuccess  = 52
	msgUserAuthBanner   = 53
	msgUserAuthInfoReq  = 60
	msgUserAuthInfoResp = 61

	clientVersion = "SSH-2.0-NetDestruct"

	// Stream cipher padding (AES-CTR).
	packetAlign = 16
)

var (
	dhGroup14P = mustBigInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF")
	dhGroup14G = big.NewInt(2)
)

func mustBigInt(hex string) *big.Int {
	n := new(big.Int)
	if _, ok := n.SetString(hex, 16); !ok {
		panic("bad dh p")
	}
	return n
}

type transport struct {
	conn      net.Conn
	clientVer []byte
	serverVer []byte
	seqOut    uint32
	seqIn     uint32
	encOut    cipher.Stream
	encIn     cipher.Stream
	macOut    hash.Hash
	macIn     hash.Hash
	macOutLen int
	macInLen  int
	sessionID []byte
	banner    string
	hostKey   []byte // server host key blob from last KEX reply
	userAuth  bool   // ssh-userauth service accepted
}

func newTransport(conn net.Conn) *transport {
	return &transport{conn: conn}
}

func (t *transport) exchangeVersions() error {
	t.clientVer = []byte(clientVersion)
	if _, err := t.conn.Write(append(append([]byte{}, t.clientVer...), '\r', '\n')); err != nil {
		return err
	}
	line, err := readSSHIdentification(t.conn)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "SSH-2.0-") && !strings.HasPrefix(line, "SSH-1.99-") {
		return fmt.Errorf("unsupported SSH version: %q", line)
	}
	t.serverVer = []byte(line)
	return nil
}

func readVersionLine(r io.Reader) (string, error) {
	var buf []byte
	b := make([]byte, 1)
	for len(buf) < 255 {
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		if b[0] == '\n' {
			break
		}
		if b[0] != '\r' {
			buf = append(buf, b[0])
		}
	}
	return string(buf), nil
}

func (t *transport) writePacket(payload []byte) error {
	padLen := packetAlign - ((5 + len(payload)) % packetAlign)
	if padLen < 4 {
		padLen += packetAlign
	}
	packetLen := 1 + len(payload) + padLen
	packet := make([]byte, 4+packetLen)
	binary.BigEndian.PutUint32(packet[0:4], uint32(packetLen))
	packet[4] = byte(padLen)
	copy(packet[5:], payload)
	if _, err := io.ReadFull(rand.Reader, packet[5+len(payload):]); err != nil {
		return err
	}

	mac := t.computeMAC(t.macOut, t.seqOut, packet)
	if t.encOut != nil {
		t.encOut.XORKeyStream(packet, packet)
	}
	if _, err := t.conn.Write(packet); err != nil {
		return err
	}
	if len(mac) > 0 {
		if _, err := t.conn.Write(mac); err != nil {
			return err
		}
	}
	t.seqOut++
	return nil
}

func (t *transport) readPacket() ([]byte, error) {
	first := make([]byte, 4)
	if _, err := io.ReadFull(t.conn, first); err != nil {
		return nil, err
	}
	if t.encIn != nil {
		t.encIn.XORKeyStream(first, first)
	}
	packetLen := binary.BigEndian.Uint32(first)
	if packetLen < 5 || packetLen > 256*1024 {
		return nil, fmt.Errorf("invalid ssh packet length %d", packetLen)
	}
	rest := make([]byte, packetLen)
	if _, err := io.ReadFull(t.conn, rest); err != nil {
		return nil, err
	}
	if t.encIn != nil {
		t.encIn.XORKeyStream(rest, rest)
	}
	full := append(first, rest...)
	if t.macInLen > 0 {
		macBuf := make([]byte, t.macInLen)
		if _, err := io.ReadFull(t.conn, macBuf); err != nil {
			return nil, err
		}
		expect := t.computeMAC(t.macIn, t.seqIn, full)
		if !hmac.Equal(macBuf, expect) {
			return nil, fmt.Errorf("ssh mac mismatch")
		}
	}
	t.seqIn++
	padLen := int(rest[0])
	if padLen < 4 || 1+padLen >= len(rest) {
		return nil, fmt.Errorf("invalid padding length")
	}
	return rest[1 : len(rest)-padLen], nil
}

func (t *transport) computeMAC(h hash.Hash, seq uint32, packet []byte) []byte {
	if h == nil {
		return nil
	}
	h.Reset()
	var seqBuf [4]byte
	binary.BigEndian.PutUint32(seqBuf[:], seq)
	h.Write(seqBuf[:])
	h.Write(packet)
	return h.Sum(nil)
}

func (t *transport) readPayload() ([]byte, error) {
	for {
		payload, err := t.readPacket()
		if err != nil {
			return nil, err
		}
		if len(payload) == 0 {
			continue
		}
		switch payload[0] {
		case msgIgnore, msgDebug, msgExtInfo:
			continue
		case msgDisconnect:
			reason := uint32(0)
			if len(payload) >= 5 {
				reason = binary.BigEndian.Uint32(payload[1:5])
			}
			return nil, fmt.Errorf("ssh disconnect (reason %d)", reason)
		case msgUserAuthBanner:
			msg, _, ok := readString(payload[1:])
			if ok {
				t.banner = string(msg)
			}
			continue
		default:
			return payload, nil
		}
	}
}

type kexResult struct {
	hashFunc func() hash.Hash
	K, H     []byte // K is wire mpint (length-prefixed)
	encAlg   string
	macAlg   string
}

type kexInitOpts struct {
	kexAlgs      string
	hostKeyAlgs  string
	encAlgs      string
	macAlgs      string
	compAlgs     string
}

func defaultKexInitOpts() kexInitOpts {
	return kexInitOpts{
		kexAlgs:     "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1",
		hostKeyAlgs: "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss",
		encAlgs:     "aes128-ctr,aes256-ctr",
		macAlgs:     "hmac-sha2-256,hmac-sha1",
		compAlgs:    "none",
	}
}

func (t *transport) doKex() (*kexResult, error) {
	return t.doKexWith(defaultKexInitOpts())
}

func (t *transport) doKexWith(opts kexInitOpts) (*kexResult, error) {
	cookie := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, cookie); err != nil {
		return nil, err
	}
	clientInit := buildKexInitWith(cookie, opts)
	if err := t.writePacket(clientInit); err != nil {
		return nil, err
	}
	serverPayload, err := t.readPayload()
	if err != nil {
		return nil, err
	}
	if serverPayload[0] != msgKexInit {
		return nil, fmt.Errorf("expected KEXINIT, got %d", serverPayload[0])
	}
	return t.doKexAfterInits(clientInit, serverPayload)
}

// doKexAfterInits completes DH/ECDH + NEWKEYS after both KEXINITs are known.
func (t *transport) doKexAfterInits(clientInit, serverInit []byte) (*kexResult, error) {
	kexAlg, _, encAlg, macAlg, err := negotiateAlgs(clientInit, serverInit)
	if err != nil {
		return nil, err
	}

	var K, H []byte
	var hashFunc func() hash.Hash
	switch kexAlg {
	case "curve25519-sha256", "curve25519-sha256@libssh.org":
		hashFunc = sha256.New
		K, H, err = t.kexCurve25519(clientInit, serverInit)
	case "diffie-hellman-group14-sha256":
		hashFunc = sha256.New
		K, H, err = t.kexDHGroup14(clientInit, serverInit, sha256.New)
	case "diffie-hellman-group14-sha1":
		hashFunc = sha1.New
		K, H, err = t.kexDHGroup14(clientInit, serverInit, sha1.New)
	default:
		return nil, fmt.Errorf("unsupported kex %q", kexAlg)
	}
	if err != nil {
		return nil, err
	}
	if t.sessionID == nil {
		t.sessionID = append([]byte(nil), H...)
	}

	res := &kexResult{hashFunc: hashFunc, K: K, H: H, encAlg: encAlg, macAlg: macAlg}

	if err := t.writePacket([]byte{msgNewKeys}); err != nil {
		return nil, err
	}
	if err := t.setupOutboundKeys(res); err != nil {
		return nil, err
	}
	nk, err := t.readPayload()
	if err != nil {
		return nil, err
	}
	if nk[0] != msgNewKeys {
		return nil, fmt.Errorf("expected NEWKEYS, got %d", nk[0])
	}
	if err := t.setupInboundKeys(res); err != nil {
		return nil, err
	}
	return res, nil
}

// readServerKexInit exchanges version banners and KEXINIT, returning the
// server's parsed algorithm name-lists. Does not complete key exchange.
func (t *transport) readServerKexInit() ([10][]string, error) {
	cookie := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, cookie); err != nil {
		return [10][]string{}, err
	}
	// Broad client offer so negotiation fields are valid; server lists are independent.
	opts := defaultKexInitOpts()
	opts.encAlgs = "aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc"
	opts.macAlgs = "hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-md5"
	opts.compAlgs = "none,zlib@openssh.com,zlib"
	clientInit := buildKexInitWith(cookie, opts)
	if err := t.writePacket(clientInit); err != nil {
		return [10][]string{}, err
	}
	serverPayload, err := t.readPayload()
	if err != nil {
		return [10][]string{}, err
	}
	if serverPayload[0] != msgKexInit {
		return [10][]string{}, fmt.Errorf("expected KEXINIT, got %d", serverPayload[0])
	}
	return parseKexInitLists(serverPayload)
}

func buildKexInit(cookie []byte) []byte {
	return buildKexInitWith(cookie, defaultKexInitOpts())
}

func buildKexInitWith(cookie []byte, opts kexInitOpts) []byte {
	if opts.kexAlgs == "" {
		opts = defaultKexInitOpts()
	}
	var b []byte
	b = append(b, msgKexInit)
	b = append(b, cookie...)
	b = appendNameList(b, opts.kexAlgs)
	b = appendNameList(b, opts.hostKeyAlgs)
	b = appendNameList(b, opts.encAlgs)
	b = appendNameList(b, opts.encAlgs)
	b = appendNameList(b, opts.macAlgs)
	b = appendNameList(b, opts.macAlgs)
	b = appendNameList(b, opts.compAlgs)
	b = appendNameList(b, opts.compAlgs)
	b = appendNameList(b, "")
	b = appendNameList(b, "")
	b = append(b, 0) // first_kex_packet_follows
	b = append(b, 0, 0, 0, 0)
	return b
}

func negotiateAlgs(clientInit, serverInit []byte) (kex, host, enc, mac string, err error) {
	cLists, err := parseKexInitLists(clientInit)
	if err != nil {
		return "", "", "", "", err
	}
	sLists, err := parseKexInitLists(serverInit)
	if err != nil {
		return "", "", "", "", err
	}
	kex = firstMatch(cLists[0], sLists[0])
	host = firstMatch(cLists[1], sLists[1])
	enc = firstMatch(cLists[2], sLists[2])
	mac = firstMatch(cLists[4], sLists[4])
	if kex == "" || host == "" || enc == "" || mac == "" {
		return "", "", "", "", fmt.Errorf("algorithm negotiation failed (kex=%q host=%q enc=%q mac=%q)", kex, host, enc, mac)
	}
	return kex, host, enc, mac, nil
}

func parseKexInitLists(payload []byte) ([10][]string, error) {
	var out [10][]string
	if len(payload) < 18 || payload[0] != msgKexInit {
		return out, fmt.Errorf("bad kexinit")
	}
	rest := payload[17:]
	for i := 0; i < 10; i++ {
		raw, next, ok := readString(rest)
		if !ok {
			return out, fmt.Errorf("bad kexinit name-list %d", i)
		}
		if len(raw) == 0 {
			out[i] = nil
		} else {
			out[i] = strings.Split(string(raw), ",")
		}
		rest = next
	}
	return out, nil
}

func firstMatch(client, server []string) string {
	set := make(map[string]bool, len(server))
	for _, s := range server {
		set[s] = true
	}
	for _, c := range client {
		if set[c] {
			return c
		}
	}
	return ""
}

func (t *transport) kexCurve25519(clientInit, serverInit []byte) (K, H []byte, err error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.PublicKey().Bytes()

	initPkt := append([]byte{msgKexECDHInit}, appendString(nil, pub)...)
	if err := t.writePacket(initPkt); err != nil {
		return nil, nil, err
	}
	reply, err := t.readPayload()
	if err != nil {
		return nil, nil, err
	}
	if reply[0] != msgKexECDHReply {
		return nil, nil, fmt.Errorf("expected ECDH_REPLY, got %d", reply[0])
	}
	rest := reply[1:]
	hostKey, rest, ok := readString(rest)
	if !ok {
		return nil, nil, fmt.Errorf("bad host key")
	}
	t.hostKey = append([]byte(nil), hostKey...)
	serverPubBytes, rest, ok := readString(rest)
	if !ok || len(serverPubBytes) != 32 {
		return nil, nil, fmt.Errorf("bad server pub")
	}
	_, _, ok = readString(rest)
	if !ok {
		return nil, nil, fmt.Errorf("bad signature")
	}
	serverPub, err := curve.NewPublicKey(serverPubBytes)
	if err != nil {
		return nil, nil, err
	}
	secret, err := priv.ECDH(serverPub)
	if err != nil {
		return nil, nil, err
	}

	K = mpintFromBig(new(big.Int).SetBytes(secret))
	h := sha256.New()
	writeString(h, t.clientVer)
	writeString(h, t.serverVer)
	writeString(h, clientInit)
	writeString(h, serverInit)
	writeString(h, hostKey)
	writeString(h, pub)
	writeString(h, serverPubBytes)
	h.Write(K)
	H = h.Sum(nil)
	return K, H, nil
}

func (t *transport) kexDHGroup14(clientInit, serverInit []byte, newHash func() hash.Hash) (K, H []byte, err error) {
	pMinus1 := new(big.Int).Sub(dhGroup14P, big.NewInt(1))
	x, err := rand.Int(rand.Reader, pMinus1)
	if err != nil {
		return nil, nil, err
	}
	if x.Sign() == 0 {
		x = big.NewInt(1)
	}
	e := new(big.Int).Exp(dhGroup14G, x, dhGroup14P)
	eMP := mpintFromBig(e)

	initPkt := append([]byte{msgKexECDHInit}, eMP...)
	if err := t.writePacket(initPkt); err != nil {
		return nil, nil, err
	}
	reply, err := t.readPayload()
	if err != nil {
		return nil, nil, err
	}
	if reply[0] != msgKexECDHReply {
		return nil, nil, fmt.Errorf("expected DH_REPLY, got %d", reply[0])
	}
	rest := reply[1:]
	hostKey, rest, ok := readString(rest)
	if !ok {
		return nil, nil, fmt.Errorf("bad host key")
	}
	t.hostKey = append([]byte(nil), hostKey...)
	fMP, rest, ok := readMPInt(rest)
	if !ok {
		return nil, nil, fmt.Errorf("bad f")
	}
	_, _, ok = readString(rest)
	if !ok {
		return nil, nil, fmt.Errorf("bad signature")
	}
	f := new(big.Int).SetBytes(fMP)
	secret := new(big.Int).Exp(f, x, dhGroup14P)
	K = mpintFromBig(secret)

	h := newHash()
	writeString(h, t.clientVer)
	writeString(h, t.serverVer)
	writeString(h, clientInit)
	writeString(h, serverInit)
	writeString(h, hostKey)
	h.Write(eMP)
	h.Write(mpintFromBig(f))
	h.Write(K)
	H = h.Sum(nil)
	return K, H, nil
}

func (t *transport) setupOutboundKeys(res *kexResult) error {
	iv := deriveKey(res.hashFunc, res.K, res.H, t.sessionID, 'A', 16)
	key := deriveKey(res.hashFunc, res.K, res.H, t.sessionID, 'C', keySize(res.encAlg))
	macKey := deriveKey(res.hashFunc, res.K, res.H, t.sessionID, 'E', macKeySize(res.macAlg))
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	t.encOut = cipher.NewCTR(block, iv)
	t.macOut = newMAC(res.macAlg, macKey)
	t.macOutLen = t.macOut.Size()
	return nil
}

func (t *transport) setupInboundKeys(res *kexResult) error {
	iv := deriveKey(res.hashFunc, res.K, res.H, t.sessionID, 'B', 16)
	key := deriveKey(res.hashFunc, res.K, res.H, t.sessionID, 'D', keySize(res.encAlg))
	macKey := deriveKey(res.hashFunc, res.K, res.H, t.sessionID, 'F', macKeySize(res.macAlg))
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	t.encIn = cipher.NewCTR(block, iv)
	t.macIn = newMAC(res.macAlg, macKey)
	t.macInLen = t.macIn.Size()
	return nil
}

func keySize(enc string) int {
	if enc == "aes256-ctr" {
		return 32
	}
	return 16
}

func macKeySize(mac string) int {
	if mac == "hmac-sha2-256" {
		return 32
	}
	return 20
}

func newMAC(alg string, key []byte) hash.Hash {
	if alg == "hmac-sha2-256" {
		return hmac.New(sha256.New, key)
	}
	return hmac.New(sha1.New, key)
}

func deriveKey(newHash func() hash.Hash, K, H, sessionID []byte, letter byte, need int) []byte {
	var out, prev []byte
	for len(out) < need {
		h := newHash()
		h.Write(K)
		h.Write(H)
		if prev == nil {
			h.Write([]byte{letter})
			h.Write(sessionID)
		} else {
			h.Write(prev)
		}
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:need]
}

func (t *transport) requestUserAuth() error {
	req := []byte{msgServiceRequest}
	req = appendString(req, []byte("ssh-userauth"))
	if err := t.writePacket(req); err != nil {
		return err
	}
	payload, err := t.readPayload()
	if err != nil {
		return err
	}
	if payload[0] != msgServiceAccept {
		return fmt.Errorf("expected SERVICE_ACCEPT, got %d", payload[0])
	}
	return nil
}

func (t *transport) listAuthMethods(user string) ([]string, error) {
	if err := t.requestUserAuth(); err != nil {
		return nil, err
	}
	authReq := []byte{msgUserAuthRequest}
	authReq = appendString(authReq, []byte(user))
	authReq = appendString(authReq, []byte("ssh-connection"))
	authReq = appendString(authReq, []byte("none"))
	if err := t.writePacket(authReq); err != nil {
		return nil, err
	}
	for {
		payload, err := t.readPayload()
		if err != nil {
			return nil, err
		}
		switch payload[0] {
		case msgUserAuthFailure:
			list, _, ok := readString(payload[1:])
			if !ok {
				return nil, fmt.Errorf("bad USERAUTH_FAILURE")
			}
			if len(list) == 0 {
				return nil, nil
			}
			return strings.Split(string(list), ","), nil
		case msgUserAuthSuccess:
			return []string{"none"}, nil
		default:
			return nil, fmt.Errorf("unexpected userauth message %d", payload[0])
		}
	}
}

func (t *transport) tryPassword(user, password string) (bool, error) {
	req := []byte{msgUserAuthRequest}
	req = appendString(req, []byte(user))
	req = appendString(req, []byte("ssh-connection"))
	req = appendString(req, []byte("password"))
	req = append(req, 0)
	req = appendString(req, []byte(password))
	if err := t.writePacket(req); err != nil {
		return false, err
	}
	return t.readAuthResult()
}

func (t *transport) tryKeyboardInteractive(user, password string) (bool, error) {
	req := []byte{msgUserAuthRequest}
	req = appendString(req, []byte(user))
	req = appendString(req, []byte("ssh-connection"))
	req = appendString(req, []byte("keyboard-interactive"))
	req = appendString(req, nil)
	req = appendString(req, nil)
	if err := t.writePacket(req); err != nil {
		return false, err
	}
	for {
		payload, err := t.readPayload()
		if err != nil {
			return false, err
		}
		switch payload[0] {
		case msgUserAuthInfoReq:
			rest := payload[1:]
			_, rest, ok := readString(rest)
			if !ok {
				return false, fmt.Errorf("bad kbd-int name")
			}
			_, rest, ok = readString(rest)
			if !ok {
				return false, fmt.Errorf("bad kbd-int instruction")
			}
			_, rest, ok = readString(rest)
			if !ok {
				return false, fmt.Errorf("bad kbd-int language")
			}
			if len(rest) < 4 {
				return false, fmt.Errorf("bad kbd-int prompt count")
			}
			n := binary.BigEndian.Uint32(rest[:4])
			rest = rest[4:]
			for i := uint32(0); i < n; i++ {
				_, rest, ok = readString(rest)
				if !ok || len(rest) < 1 {
					return false, fmt.Errorf("bad kbd-int prompt")
				}
				rest = rest[1:]
			}
			resp := []byte{msgUserAuthInfoResp}
			var nbuf [4]byte
			binary.BigEndian.PutUint32(nbuf[:], n)
			resp = append(resp, nbuf[:]...)
			for i := uint32(0); i < n; i++ {
				resp = appendString(resp, []byte(password))
			}
			if err := t.writePacket(resp); err != nil {
				return false, err
			}
		case msgUserAuthSuccess:
			return true, nil
		case msgUserAuthFailure:
			return false, nil
		default:
			return false, fmt.Errorf("unexpected kbd-int message %d", payload[0])
		}
	}
}

func (t *transport) readAuthResult() (bool, error) {
	for {
		payload, err := t.readPayload()
		if err != nil {
			return false, err
		}
		switch payload[0] {
		case msgUserAuthSuccess:
			return true, nil
		case msgUserAuthFailure:
			return false, nil
		default:
			return false, fmt.Errorf("unexpected userauth message %d", payload[0])
		}
	}
}

func hasAuthMethod(methods []string, want string) bool {
	for _, m := range methods {
		if strings.TrimSpace(m) == want {
			return true
		}
	}
	return false
}

// msgUserAuthPKOK shares wire number 60 with SSH_MSG_USERAUTH_INFO_REQUEST.
const msgUserAuthPKOK = msgUserAuthInfoReq

// publickeyCanAuth probes whether the server would accept keyBlob for user
// without proving possession (RFC 4252 publickey query / libssh2 publickey_canauth).
func (t *transport) publickeyCanAuth(user string, keyBlob []byte) (bool, error) {
	alg, _, ok := readString(keyBlob)
	if !ok || len(alg) == 0 {
		return false, fmt.Errorf("invalid public key blob")
	}
	if err := t.ensureUserAuth(); err != nil {
		return false, err
	}
	req := []byte{msgUserAuthRequest}
	req = appendString(req, []byte(user))
	req = appendString(req, []byte("ssh-connection"))
	req = appendString(req, []byte("publickey"))
	req = append(req, 0) // FALSE — query only
	req = appendString(req, alg)
	req = appendString(req, keyBlob)
	if err := t.writePacket(req); err != nil {
		return false, err
	}
	for {
		payload, err := t.readPayload()
		if err != nil {
			return false, err
		}
		switch payload[0] {
		case msgUserAuthPKOK:
			return true, nil
		case msgUserAuthFailure:
			return false, nil
		case msgUserAuthSuccess:
			return true, nil
		default:
			return false, fmt.Errorf("unexpected userauth message %d", payload[0])
		}
	}
}

func (t *transport) ensureUserAuth() error {
	if t.userAuth {
		return nil
	}
	if err := t.requestUserAuth(); err != nil {
		return err
	}
	t.userAuth = true
	return nil
}

func (t *transport) tryAuth(user, password string, methods []string) (bool, error) {
	if hasAuthMethod(methods, "password") {
		ok, err := t.tryPassword(user, password)
		if err != nil || ok {
			return ok, err
		}
	}
	if hasAuthMethod(methods, "keyboard-interactive") {
		return t.tryKeyboardInteractive(user, password)
	}
	if !hasAuthMethod(methods, "password") {
		return false, fmt.Errorf("target does not support password or keyboard-interactive auth")
	}
	return false, nil
}

func appendNameList(b []byte, s string) []byte {
	return appendString(b, []byte(s))
}

func appendString(b, s []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
	b = append(b, lenBuf[:]...)
	return append(b, s...)
}

func readString(b []byte) (val, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, b, false
	}
	n := binary.BigEndian.Uint32(b[:4])
	if uint32(len(b)-4) < n {
		return nil, b, false
	}
	return b[4 : 4+n], b[4+n:], true
}

func readMPInt(b []byte) (val, rest []byte, ok bool) {
	return readString(b)
}

func writeString(h hash.Hash, s []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
	h.Write(lenBuf[:])
	h.Write(s)
}

func mpintFromBig(n *big.Int) []byte {
	if n.Sign() == 0 {
		return []byte{0, 0, 0, 0}
	}
	b := n.Bytes()
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out[:4], uint32(len(b)))
	copy(out[4:], b)
	return out
}
