package ssh

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// KeyEnumer tests whether SSH public keys (or publics derived from cleartext
// private keys) are accepted for authentication.
type KeyEnumer struct {
	Target   string
	Port     int
	KeyPath  string // --file: single key file, concatenated keys, or directory
	Username string
	UserList string
	Timeout  time.Duration
	Out      io.Writer
}

type loadedKey struct {
	blob     []byte // SSH wire public key blob
	comment  string
	source   string // file path or "inline"
	hasPriv  bool
	fp       string // MD5 colon fingerprint
	fullLine string // "type base64 [comment]"
}

// Run loads keys from --file (file or directory) and probes acceptance per user.
func (k *KeyEnumer) Run() error {
	host := strings.TrimSpace(k.Target)
	keyPath := strings.TrimSpace(k.KeyPath)
	if host == "" {
		return fmt.Errorf("--ssh --key-enum requires --target <ip>")
	}
	if keyPath == "" {
		return fmt.Errorf("--ssh --key-enum requires --file <key-file|directory>")
	}

	users, err := k.loadUsers()
	if err != nil {
		return err
	}
	if len(users) == 0 {
		return fmt.Errorf("--ssh --key-enum requires --username <user> or --userlist <file>")
	}

	keys, err := loadCleartextKeys(keyPath)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("no valid cleartext SSH keys found in %s", keyPath)
	}

	port := k.Port
	if port <= 0 {
		port = defaultPort
	}
	timeout := k.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	out := k.Out
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
	fmt.Fprintf(out, "%s Target: %s\n", sshTag, addr)
	if banner, err := GrabBanner(ip.String(), port, timeout); err == nil && banner != "" {
		fmt.Fprintf(out, "%s Banner: %s\n", sshTag, banner)
	}
	fmt.Fprintf(out, "%s Trying %d cleartext key(s) for %d user(s)\n",
		sshTag, len(keys), len(users))

	accepted := 0
	tried := 0
	for _, user := range users {
		for _, key := range keys {
			tried++
			ok, err := tryKeyOnce(addr, timeout, user, key.blob)
			if err != nil {
				// Soft-fail on connection/protocol errors; continue other keys.
				continue
			}
			priv := "No"
			if key.hasPriv {
				priv = "Yes"
			}
			info := key.comment
			if info != "" {
				info = "- " + info
			}
			if !ok {
				continue
			}
			accepted++
			fmt.Fprintf(out, "- %sPublic key accepted: '%s' with key '%s' (Private Key: %s) %s\x1b[0m\n",
				foundTag, user, key.fp, priv, info)
			if key.source != "" && key.source != "inline" {
				fmt.Fprintf(out, "      Source: %s\n", key.source)
			}
			if key.fullLine != "" {
				fmt.Fprintf(out, "      %s\n", key.fullLine)
			}
		}
	}

	fmt.Fprintf(out, "%s Done: %d accepted / %d tried\n", sshTag, accepted, tried)
	return nil
}

func (k *KeyEnumer) loadUsers() ([]string, error) {
	var users []string
	seen := map[string]bool{}
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		users = append(users, u)
	}
	add(k.Username)
	path := strings.TrimSpace(k.UserList)
	if path == "" {
		return users, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open userlist: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		add(line)
	}
	return users, sc.Err()
}

func tryKeyOnce(addr string, timeout time.Duration, user string, blob []byte) (bool, error) {
	tr, err := dialKex(addr, timeout)
	if err != nil {
		return false, err
	}
	defer tr.conn.Close()
	_ = tr.conn.SetDeadline(time.Now().Add(timeout * 3))
	return tr.publickeyCanAuth(user, blob)
}

func loadCleartextKeys(path string) ([]loadedKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if st.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		var all []loadedKey
		seen := map[string]bool{}
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, ".") || e.IsDir() {
				continue
			}
			fp := filepath.Join(path, name)
			b, err := os.ReadFile(fp)
			if err != nil {
				continue
			}
			for _, k := range parseKeyMaterial(string(b), fp) {
				if seen[k.fp] {
					continue
				}
				seen[k.fp] = true
				all = append(all, k)
			}
		}
		return all, nil
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseKeyMaterial(string(b), path), nil
}

func parseKeyMaterial(data, source string) []loadedKey {
	var out []loadedKey
	seen := map[string]bool{}
	add := func(k loadedKey) {
		if len(k.blob) == 0 || k.fp == "" || seen[k.fp] {
			return
		}
		seen[k.fp] = true
		if k.source == "" {
			k.source = source
		}
		out = append(out, k)
	}

	// authorized_keys / OpenSSH public key lines
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, ok := parseAuthorizedKeysLine(line, source); ok {
			add(k)
		}
	}

	// PEM blocks (RSA/DSA/EC/OPENSSH private or public)
	rest := []byte(data)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
			continue // skips encrypted private keys
		}
		switch {
		case block.Type == "OPENSSH PRIVATE KEY":
			if k, ok := publicFromOpenSSHPrivate(block.Bytes, source); ok {
				add(k)
			}
		case strings.Contains(block.Type, "PRIVATE KEY"):
			if k, ok := publicFromPEMPrivate(block, source); ok {
				add(k)
			}
		case strings.Contains(block.Type, "PUBLIC KEY"):
			if k, ok := publicFromPEMPublic(block, source); ok {
				add(k)
			}
		}
	}
	return out
}

func parseAuthorizedKeysLine(line, source string) (loadedKey, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return loadedKey{}, false
	}
	alg := fields[0]
	if !isSSHPubAlg(alg) {
		return loadedKey{}, false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(blob) == 0 {
		return loadedKey{}, false
	}
	// authorized_keys base64 is the full wire blob (algorithm string + key data).
	name, _, ok := readString(blob)
	if !ok || string(name) != alg {
		return loadedKey{}, false
	}
	comment := ""
	if len(fields) > 2 {
		comment = strings.Join(fields[2:], " ")
	}
	fp := md5Fingerprint(blob)
	return loadedKey{
		blob:     blob,
		comment:  comment,
		source:   source,
		hasPriv:  false,
		fp:       fp,
		fullLine: alg + " " + fields[1] + optionalComment(comment),
	}, true
}

func optionalComment(c string) string {
	if c == "" {
		return ""
	}
	return " " + c
}

func isSSHPubAlg(alg string) bool {
	switch alg {
	case "ssh-rsa", "ssh-dss", "ssh-ed25519", "ssh-ed448":
		return true
	}
	return strings.HasPrefix(alg, "ecdsa-sha2-") ||
		strings.HasPrefix(alg, "sk-ssh-") ||
		strings.HasPrefix(alg, "sk-ecdsa-")
}

func publicFromPEMPrivate(block *pem.Block, source string) (loadedKey, bool) {
	var pub interface{}
	var err error
	switch {
	case block.Type == "RSA PRIVATE KEY":
		pub, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case block.Type == "EC PRIVATE KEY":
		pub, err = x509.ParseECPrivateKey(block.Bytes)
	case block.Type == "DSA PRIVATE KEY":
		priv, ok := parseDSAPrivateKey(block.Bytes)
		if !ok {
			return loadedKey{}, false
		}
		blob := marshalDSASHA1Public(priv)
		fp := md5Fingerprint(blob)
		return loadedKey{
			blob: blob, source: source, hasPriv: true, fp: fp,
			fullLine: "ssh-dss " + base64.StdEncoding.EncodeToString(blob),
		}, true
	case block.Type == "PRIVATE KEY": // PKCS#8
		key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return loadedKey{}, false
		}
		pub = key
	default:
		return loadedKey{}, false
	}
	if err != nil {
		return loadedKey{}, false
	}
	blob, alg, ok := marshalSSHPublic(pub)
	if !ok {
		return loadedKey{}, false
	}
	fp := md5Fingerprint(blob)
	return loadedKey{
		blob: blob, source: source, hasPriv: true, fp: fp,
		fullLine: alg + " " + base64.StdEncoding.EncodeToString(blob),
	}, true
}

func publicFromPEMPublic(block *pem.Block, source string) (loadedKey, bool) {
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return loadedKey{}, false
	}
	blob, alg, ok := marshalSSHPublic(pub)
	if !ok {
		return loadedKey{}, false
	}
	fp := md5Fingerprint(blob)
	return loadedKey{
		blob: blob, source: source, hasPriv: false, fp: fp,
		fullLine: alg + " " + base64.StdEncoding.EncodeToString(blob),
	}, true
}

func publicFromOpenSSHPrivate(data []byte, source string) (loadedKey, bool) {
	const magic = "openssh-key-v1\x00"
	if !strings.HasPrefix(string(data), magic) {
		return loadedKey{}, false
	}
	rest := data[len(magic):]
	cipherName, rest, ok := readString(rest)
	if !ok {
		return loadedKey{}, false
	}
	kdfName, rest, ok := readString(rest)
	if !ok {
		return loadedKey{}, false
	}
	_, rest, ok = readString(rest) // kdf options
	if !ok {
		return loadedKey{}, false
	}
	if string(cipherName) != "none" || string(kdfName) != "none" {
		return loadedKey{}, false // encrypted — skip (cleartext only)
	}
	if len(rest) < 4 {
		return loadedKey{}, false
	}
	nkeys := binary.BigEndian.Uint32(rest[:4])
	rest = rest[4:]
	if nkeys < 1 {
		return loadedKey{}, false
	}
	pubBlob, _, ok := readString(rest)
	if !ok || len(pubBlob) == 0 {
		return loadedKey{}, false
	}
	alg, _, ok := readString(pubBlob)
	if !ok {
		return loadedKey{}, false
	}
	fp := md5Fingerprint(pubBlob)
	return loadedKey{
		blob: pubBlob, source: source, hasPriv: true, fp: fp,
		fullLine: string(alg) + " " + base64.StdEncoding.EncodeToString(pubBlob),
	}, true
}

func marshalSSHPublic(key interface{}) (blob []byte, alg string, ok bool) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return marshalRSAPublic(&k.PublicKey)
	case *rsa.PublicKey:
		return marshalRSAPublic(k)
	case *ecdsa.PrivateKey:
		return marshalECDSAPublic(&k.PublicKey)
	case *ecdsa.PublicKey:
		return marshalECDSAPublic(k)
	case ed25519.PrivateKey:
		return marshalEd25519Public(k.Public().(ed25519.PublicKey))
	case ed25519.PublicKey:
		return marshalEd25519Public(k)
	default:
		return nil, "", false
	}
}

func marshalRSAPublic(pub *rsa.PublicKey) ([]byte, string, bool) {
	var b []byte
	b = appendString(b, []byte("ssh-rsa"))
	b = appendMPInt(b, big.NewInt(int64(pub.E)))
	b = appendMPInt(b, pub.N)
	return b, "ssh-rsa", true
}

func marshalEd25519Public(pub ed25519.PublicKey) ([]byte, string, bool) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, "", false
	}
	var b []byte
	b = appendString(b, []byte("ssh-ed25519"))
	b = appendString(b, pub)
	return b, "ssh-ed25519", true
}

func marshalECDSAPublic(pub *ecdsa.PublicKey) ([]byte, string, bool) {
	var curveName string
	switch pub.Curve {
	case elliptic.P256():
		curveName = "nistp256"
	case elliptic.P384():
		curveName = "nistp384"
	case elliptic.P521():
		curveName = "nistp521"
	default:
		return nil, "", false
	}
	alg := "ecdsa-sha2-" + curveName
	var b []byte
	b = appendString(b, []byte(alg))
	b = appendString(b, []byte(curveName))
	b = appendString(b, marshalECPoint(pub))
	return b, alg, true
}

func marshalECPoint(pub *ecdsa.PublicKey) []byte {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 1+2*byteLen)
	out[0] = 0x04 // uncompressed
	pub.X.FillBytes(out[1 : 1+byteLen])
	pub.Y.FillBytes(out[1+byteLen:])
	return out
}

type dsaPrivateKey struct {
	Version int
	P, Q, G *big.Int
	Y, X    *big.Int
}

func parseDSAPrivateKey(der []byte) (*dsaPrivateKey, bool) {
	var k dsaPrivateKey
	if _, err := asn1.Unmarshal(der, &k); err != nil {
		return nil, false
	}
	if k.P == nil || k.Q == nil || k.G == nil || k.Y == nil {
		return nil, false
	}
	return &k, true
}

func marshalDSASHA1Public(priv *dsaPrivateKey) []byte {
	var b []byte
	b = appendString(b, []byte("ssh-dss"))
	b = appendMPInt(b, priv.P)
	b = appendMPInt(b, priv.Q)
	b = appendMPInt(b, priv.G)
	b = appendMPInt(b, priv.Y)
	return b
}

func appendMPInt(b []byte, n *big.Int) []byte {
	if n == nil || n.Sign() == 0 {
		return appendString(b, nil)
	}
	raw := n.Bytes()
	if raw[0]&0x80 != 0 {
		raw = append([]byte{0x00}, raw...)
	}
	return appendString(b, raw)
}

func md5Fingerprint(blob []byte) string {
	sum := md5.Sum(blob)
	parts := make([]string, len(sum))
	for i, v := range sum {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, ":")
}
