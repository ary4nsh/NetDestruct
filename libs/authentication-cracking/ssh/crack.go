package ssh

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

const tag = "\x1b[33m[SSH]\x1b[0m"

// Cracker extracts ssh2john-style hashes from an encrypted SSH private key file
// and optionally runs a dictionary attack.
//
//	--ssh --file id_rsa
//	--ssh --file id_rsa --crack --wordlist rockyou.txt
type Cracker struct {
	KeyFile  string
	Wordlist string
	Crack    bool
}

type sshHash struct {
	index    int
	fileName string
	keyType  string // RSA, DSA, EC, OPENSSH
	cipher   string
	sshngTyp int
	salt     []byte
	data     []byte // full base64-decoded private key blob
	rounds   int    // OpenSSH bcrypt rounds
	ctOffset int    // OpenSSH ciphertext offset
	ctLen    int    // OpenSSH encrypted blob length (0 = to EOF)
	rawLine  string
}

func (c *Cracker) Run() error {
	path := strings.TrimSpace(c.KeyFile)
	if path == "" {
		return fmt.Errorf("--ssh requires --file <private-key>")
	}

	hashes, err := parsePrivateKeyFile(path)
	if err != nil {
		return err
	}
	if len(hashes) == 0 {
		return fmt.Errorf("no encrypted SSH private keys found in %s", path)
	}

	fmt.Printf("%s Reading %s\n\n", tag, path)

	hf, err := os.Create("ssh-hashes.txt")
	if err != nil {
		return fmt.Errorf("create ssh-hashes.txt: %w", err)
	}
	defer hf.Close()

	for i, h := range hashes {
		fmt.Printf("=== SSH Private Key #%d ===\n", i+1)
		fmt.Printf("- File:    %s\n", h.fileName)
		fmt.Printf("- Type:    %s\n", h.keyType)
		fmt.Printf("- Cipher:  %s\n", h.cipher)
		fmt.Printf("- Salt:    %s\n", hex.EncodeToString(h.salt))
		if h.rounds > 0 {
			fmt.Printf("- Rounds:  %d (bcrypt_pbkdf)\n", h.rounds)
		}
		fmt.Printf("- Format:  $sshng$%d$\n", h.sshngTyp)
		fmt.Printf("- Hash:    %s\n\n", h.rawLine)
		fmt.Fprintln(hf, h.rawLine)
	}

	fmt.Printf("=== SUMMARY ===\n")
	fmt.Printf("Encrypted keys found: %d\n", len(hashes))
	fmt.Printf("Hashes written to ssh-hashes.txt: %d\n", len(hashes))

	if !c.Crack {
		return nil
	}
	if c.Wordlist == "" {
		fmt.Printf("\n%s --crack requires --wordlist <file>\n", tag)
		return nil
	}
	return crackHashes(hashes, c.Wordlist)
}

func parsePrivateKeyFile(path string) ([]sshHash, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	lines := splitLines(string(raw))
	base := filepath.Base(path)

	var out []sshHash
	i := 0
	keyIdx := 0
	for i < len(lines) {
		line := strings.TrimSpace(lines[i])
		var tagName, keyType string
		var ktype int
		switch {
		case strings.Contains(line, "BEGIN RSA PRIVATE KEY"):
			tagName, keyType, ktype = "RSA", "RSA", 0
		case strings.Contains(line, "BEGIN DSA PRIVATE KEY"):
			tagName, keyType, ktype = "DSA", "DSA", 1
		case strings.Contains(line, "BEGIN OPENSSH PRIVATE KEY"):
			tagName, keyType, ktype = "OPENSSH", "OPENSSH", 2
		case strings.Contains(line, "BEGIN EC PRIVATE KEY"):
			tagName, keyType, ktype = "EC", "EC", 3
		default:
			i++
			continue
		}

		beginMarker := "-----BEGIN " + tagName + " PRIVATE KEY-----"
		endMarker := "-----END " + tagName + " PRIVATE KEY-----"
		for i < len(lines) && strings.TrimSpace(lines[i]) != beginMarker {
			i++
		}
		if i >= len(lines) {
			break
		}
		i++ // past BEGIN

		headers := map[string]string{}
		for i < len(lines) {
			l := strings.TrimSpace(lines[i])
			if !strings.Contains(l, ": ") {
				break
			}
			parts := strings.SplitN(l, ": ", 2)
			headers[strings.ToLower(parts[0])] = strings.TrimSpace(parts[1])
			i++
		}

		var b64 strings.Builder
		for i < len(lines) && strings.TrimSpace(lines[i]) != endMarker {
			b64.WriteString(strings.TrimSpace(lines[i]))
			i++
		}
		if i < len(lines) {
			i++ // past END
		}

		data, err := base64.StdEncoding.DecodeString(b64.String())
		if err != nil {
			return nil, fmt.Errorf("base64 decode key #%d: %w", keyIdx+1, err)
		}

		h, err := buildHash(base, keyIdx, keyType, ktype, headers, data)
		if err != nil {
			if strings.Contains(err.Error(), "no password") {
				fmt.Fprintf(os.Stderr, "%s %s key #%d has no password (skipped)\n", tag, keyType, keyIdx+1)
				keyIdx++
				continue
			}
			return nil, err
		}
		out = append(out, *h)
		keyIdx++
	}
	return out, nil
}

func buildHash(base string, idx int, keyType string, ktype int, headers map[string]string, data []byte) (*sshHash, error) {
	name := base
	if idx > 0 {
		name = fmt.Sprintf("%s_%d", base, idx+1)
	}

	var cipherName string
	var salt []byte
	var sshngTyp, rounds, ctOffset, ctLen int

	if ktype == 2 {
		var err error
		cipherName, salt, rounds, ctOffset, ctLen, err = parseOpenSSH(data)
		if err != nil {
			return nil, err
		}
		switch cipherName {
		case "aes256-cbc":
			sshngTyp = 2
			cipherName = "AES-256-CBC"
		case "aes256-ctr":
			sshngTyp = 6
			cipherName = "AES-256-CTR"
		default:
			return nil, fmt.Errorf("unsupported OpenSSH cipher %q", cipherName)
		}
	} else {
		if _, ok := headers["proc-type"]; !ok {
			return nil, fmt.Errorf("no password")
		}
		dek, ok := headers["dek-info"]
		if !ok {
			return nil, fmt.Errorf("missing DEK-Info")
		}
		parts := strings.SplitN(dek, ",", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("bad DEK-Info")
		}
		cipherName = strings.ToUpper(strings.TrimSpace(parts[0]))
		var err error
		salt, err = hex.DecodeString(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("bad DEK-Info salt: %w", err)
		}
		sshngTyp, err = pemSSHNGType(cipherName, keyType, len(salt))
		if err != nil {
			return nil, err
		}
	}

	dataHex := hex.EncodeToString(data)
	saltHex := hex.EncodeToString(salt)
	var raw string
	if ktype == 2 {
		raw = fmt.Sprintf("%s:$sshng$%d$%d$%s$%d$%s$%d$%d",
			name, sshngTyp, len(salt), saltHex, len(data), dataHex, rounds, ctOffset)
	} else {
		raw = fmt.Sprintf("%s:$sshng$%d$%d$%s$%d$%s",
			name, sshngTyp, len(salt), saltHex, len(data), dataHex)
	}

	return &sshHash{
		index:    idx + 1,
		fileName: name,
		keyType:  keyType,
		cipher:   cipherName,
		sshngTyp: sshngTyp,
		salt:     salt,
		data:     data,
		rounds:   rounds,
		ctOffset: ctOffset,
		ctLen:    ctLen,
		rawLine:  raw,
	}, nil
}

func pemSSHNGType(cipher, keyType string, saltLen int) (int, error) {
	switch cipher {
	case "DES-EDE3-CBC":
		return 0, nil
	case "AES-128-CBC":
		if keyType == "EC" {
			return 3, nil
		}
		return 1, nil
	case "AES-192-CBC":
		return 4, nil
	case "AES-256-CBC":
		return 5, nil
	case "DES-CBC":
		if saltLen == 8 {
			return 6, nil
		}
		return 0, fmt.Errorf("unsupported DES salt length %d", saltLen)
	default:
		return 0, fmt.Errorf("unsupported cipher %q", cipher)
	}
}

func parseOpenSSH(data []byte) (cipherName string, salt []byte, rounds, ctOffset, ctLen int, err error) {
	const magic = "openssh-key-v1\x00"
	if !strings.HasPrefix(string(data), magic) {
		return "", nil, 0, 0, 0, fmt.Errorf("missing openssh-key-v1 magic")
	}
	off := len(magic)
	cipherName, off, err = readSSHString(data, off)
	if err != nil {
		return "", nil, 0, 0, 0, err
	}
	if cipherName == "none" {
		return "", nil, 0, 0, 0, fmt.Errorf("no password")
	}
	_, off, err = readSSHString(data, off) // kdfname
	if err != nil {
		return "", nil, 0, 0, 0, err
	}
	kdfOpts, off, err := readSSHBytes(data, off)
	if err != nil {
		return "", nil, 0, 0, 0, err
	}
	if len(kdfOpts) < 4+16+4 {
		return "", nil, 0, 0, 0, fmt.Errorf("bad bcrypt kdf options")
	}
	saltLen := binary.BigEndian.Uint32(kdfOpts[0:4])
	if saltLen != 16 || int(4+saltLen+4) > len(kdfOpts) {
		return "", nil, 0, 0, 0, fmt.Errorf("unexpected bcrypt salt length %d", saltLen)
	}
	salt = append([]byte(nil), kdfOpts[4:4+saltLen]...)
	rounds = int(binary.BigEndian.Uint32(kdfOpts[4+saltLen : 4+saltLen+4]))
	if rounds == 0 {
		rounds = 16
	}
	if off+4 > len(data) {
		return "", nil, 0, 0, 0, fmt.Errorf("truncated OpenSSH key")
	}
	off += 4 // nkeys
	_, off, err = readSSHBytes(data, off) // public key
	if err != nil {
		return "", nil, 0, 0, 0, err
	}
	if off+4 > len(data) {
		return "", nil, 0, 0, 0, fmt.Errorf("truncated encrypted blob length")
	}
	encLen := int(binary.BigEndian.Uint32(data[off : off+4]))
	off += 4
	ctOffset = off
	if off+encLen > len(data) {
		return "", nil, 0, 0, 0, fmt.Errorf("truncated encrypted private keys")
	}
	return cipherName, salt, rounds, ctOffset, encLen, nil
}

func readSSHString(b []byte, off int) (string, int, error) {
	raw, off, err := readSSHBytes(b, off)
	if err != nil {
		return "", off, err
	}
	return string(raw), off, nil
}

func readSSHBytes(b []byte, off int) ([]byte, int, error) {
	if off+4 > len(b) {
		return nil, off, fmt.Errorf("truncated string length")
	}
	n := int(binary.BigEndian.Uint32(b[off : off+4]))
	off += 4
	if n < 0 || off+n > len(b) {
		return nil, off, fmt.Errorf("truncated string body")
	}
	return append([]byte(nil), b[off:off+n]...), off + n, nil
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

func crackHashes(hashes []sshHash, wordlistPath string) error {
	wl, err := os.Open(wordlistPath)
	if err != nil {
		return fmt.Errorf("open wordlist %s: %w", wordlistPath, err)
	}
	defer wl.Close()

	fmt.Printf("\n%s Starting dictionary attack on %d hash(es) using %s...\n", tag, len(hashes), wordlistPath)

	done := make([]bool, len(hashes))
	remaining := len(hashes)
	tested := 0
	cracked := 0

	sc := bufio.NewScanner(wl)
	sc.Buffer(make([]byte, 0, 65536), 1024*1024)
	for sc.Scan() {
		pass := sc.Text()
		tested++
		for i := range hashes {
			if done[i] {
				continue
			}
			if tryPassword(&hashes[i], pass) {
				fmt.Printf("\n%s [+] CRACKED: \"%s\"\n", tag, pass)
				fmt.Printf("    Hash #%d (%s / %s): %s\n", hashes[i].index, hashes[i].keyType, hashes[i].cipher, hashes[i].fileName)
				done[i] = true
				cracked++
				remaining--
			}
		}
		if remaining == 0 {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read wordlist: %w", err)
	}

	fmt.Printf("\n%s Tested %d passwords. Cracked %d / %d hashes.\n", tag, tested, cracked, len(hashes))
	return nil
}

func tryPassword(h *sshHash, password string) bool {
	if h.keyType == "OPENSSH" {
		return tryOpenSSH(h, password)
	}
	return tryPEM(h, password)
}

func tryPEM(h *sshHash, password string) bool {
	keyLen, ivLen, blockSize := pemCipherParams(h.cipher)
	if keyLen == 0 {
		return false
	}
	// OpenSSL traditional PEM: DEK-Info salt is the IV; key from EVP_BytesToKey(MD5).
	key := evpBytesToKey(password, h.salt, keyLen)
	iv := make([]byte, ivLen)
	copy(iv, h.salt)
	pt, err := decryptCBC(h.cipher, key, iv, h.data)
	if err != nil {
		return false
	}
	plain, ok := pkcs7Unpad(pt, blockSize)
	if !ok {
		return false
	}
	return validPEMPrivateKey(h.keyType, plain)
}

func pemCipherParams(cipherName string) (keyLen, ivLen, blockSize int) {
	switch cipherName {
	case "DES-CBC":
		return 8, 8, 8
	case "DES-EDE3-CBC":
		return 24, 8, 8
	case "AES-128-CBC":
		return 16, 16, 16
	case "AES-192-CBC":
		return 24, 16, 16
	case "AES-256-CBC":
		return 32, 16, 16
	default:
		return 0, 0, 0
	}
}

func evpBytesToKey(password string, salt []byte, need int) []byte {
	// OpenSSL EVP_BytesToKey(MD5) only consumes PKCS5_SALT_LEN (8) salt bytes,
	// even when the CBC IV (DEK-Info) is longer (e.g. 16 for AES).
	if len(salt) > 8 {
		salt = salt[:8]
	}
	var out, prev []byte
	pass := []byte(password)
	for len(out) < need {
		h := md5.New()
		h.Write(prev)
		h.Write(pass)
		h.Write(salt)
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:need]
}

func decryptCBC(cipherName string, key, iv, ct []byte) ([]byte, error) {
	if len(ct) == 0 || len(ct)%8 != 0 && (cipherName == "DES-CBC" || cipherName == "DES-EDE3-CBC") {
		return nil, fmt.Errorf("bad ciphertext length")
	}
	var block cipher.Block
	var err error
	switch cipherName {
	case "DES-CBC":
		block, err = des.NewCipher(key)
	case "DES-EDE3-CBC":
		block, err = des.NewTripleDESCipher(key)
	case "AES-128-CBC", "AES-192-CBC", "AES-256-CBC":
		if len(ct)%aes.BlockSize != 0 {
			return nil, fmt.Errorf("bad aes length")
		}
		block, err = aes.NewCipher(key)
	default:
		return nil, fmt.Errorf("unsupported")
	}
	if err != nil {
		return nil, err
	}
	if len(ct)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("bad block alignment")
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	return pt, nil
}

func pkcs7Unpad(pt []byte, blockSize int) ([]byte, bool) {
	if blockSize <= 0 || len(pt) == 0 || len(pt)%blockSize != 0 {
		return nil, false
	}
	pad := int(pt[len(pt)-1])
	if pad < 1 || pad > blockSize || pad > len(pt) {
		return nil, false
	}
	for i := 0; i < pad; i++ {
		if pt[len(pt)-1-i] != byte(pad) {
			return nil, false
		}
	}
	return pt[:len(pt)-pad], true
}

// validPEMPrivateKey fully parses the decrypted DER — padding alone is far too
// weak and produces false positives (e.g. "roxana" on rockyou).
func validPEMPrivateKey(keyType string, der []byte) bool {
	switch keyType {
	case "RSA":
		_, err := x509.ParsePKCS1PrivateKey(der)
		return err == nil
	case "EC":
		_, err := x509.ParseECPrivateKey(der)
		return err == nil
	case "DSA":
		return parseDSAPrivateKeyDER(der)
	default:
		return false
	}
}

type dsaPrivateKeyDER struct {
	Version int
	P       *big.Int
	Q       *big.Int
	G       *big.Int
	Y       *big.Int
	X       *big.Int
}

func parseDSAPrivateKeyDER(der []byte) bool {
	var k dsaPrivateKeyDER
	rest, err := asn1.Unmarshal(der, &k)
	if err != nil || len(rest) != 0 {
		return false
	}
	if k.Version != 0 {
		return false
	}
	if k.P == nil || k.Q == nil || k.G == nil || k.Y == nil || k.X == nil {
		return false
	}
	// Basic DSA parameter sanity (OpenSSL traditional DSA PEM).
	if k.P.Sign() <= 0 || k.Q.Sign() <= 0 || k.G.Sign() <= 0 || k.Y.Sign() <= 0 || k.X.Sign() <= 0 {
		return false
	}
	if k.Q.BitLen() < 160 || k.P.BitLen() < 512 {
		return false
	}
	if k.X.Cmp(k.Q) >= 0 {
		return false
	}
	return true
}

func tryOpenSSH(h *sshHash, password string) bool {
	if h.ctOffset <= 0 || h.ctOffset >= len(h.data) {
		return false
	}
	end := len(h.data)
	if h.ctLen > 0 {
		end = h.ctOffset + h.ctLen
		if end > len(h.data) {
			return false
		}
	}
	ct := h.data[h.ctOffset:end]
	if len(ct) < 16 || len(ct)%16 != 0 {
		return false
	}
	keyiv := make([]byte, 48) // 32 key + 16 iv
	if err := bcryptPBKDF([]byte(password), h.salt, keyiv, h.rounds); err != nil {
		return false
	}
	key, iv := keyiv[:32], keyiv[32:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	pt := make([]byte, len(ct))
	switch h.cipher {
	case "AES-256-CBC":
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	case "AES-256-CTR":
		cipher.NewCTR(block, iv).XORKeyStream(pt, ct)
	default:
		return false
	}
	if len(pt) < 8 {
		return false
	}
	c1 := binary.BigEndian.Uint32(pt[0:4])
	c2 := binary.BigEndian.Uint32(pt[4:8])
	return c1 == c2
}
