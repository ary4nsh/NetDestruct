package ciscopass

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"os"
	"regexp"
	"strings"
)

type hash8 struct {
	context string
	full    string
	salt    string
	encoded string
}

var (
	reEnable8   = regexp.MustCompile(`enable\s+secret\s+(?:\d+\s+)?8\s+(\$8\$\S+)`)
	reUsername8 = regexp.MustCompile(`username\s+(\S+)\s+(?:privilege\s+\d+\s+)?secret\s+8\s+(\$8\$\S+)`)
)

func (c *Cracker) runType8() error {
	if c.Wordlist == "" {
		return fmt.Errorf("--type8 requires --wordlist")
	}

	var hashes []hash8
	if c.HashValue != "" {
		h := parseHash8(c.HashValue)
		if h == nil {
			return fmt.Errorf("invalid Type 8 hash: %q (expected $8$salt$hash)", c.HashValue)
		}
		h.context = "direct hash"
		hashes = []hash8{*h}
	} else {
		var err error
		hashes, err = parseConfig8(c.ConfigFile)
		if err != nil {
			return err
		}
		if len(hashes) == 0 {
			fmt.Println("No Type 8 hashes found in config file.")
			return nil
		}
	}

	fmt.Printf("Found %d Type 8 hash(es):\n", len(hashes))
	for i, h := range hashes {
		fmt.Printf("\n=== Type 8 Hash #%d ===\n", i+1)
		fmt.Printf("- Context: %s\n", h.context)
		fmt.Printf("- Hash:    %s\n", h.full)
		fmt.Printf("- Salt:    %s\n", h.salt)
	}

	return crack8(hashes, c.Wordlist)
}

func parseConfig8(path string) ([]hash8, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var out []hash8
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if m := reEnable8.FindStringSubmatch(line); m != nil {
			if h := parseHash8(m[1]); h != nil {
				h.context = "enable secret"
				out = append(out, *h)
			}
		} else if m := reUsername8.FindStringSubmatch(line); m != nil {
			if h := parseHash8(m[2]); h != nil {
				h.context = "username " + m[1]
				out = append(out, *h)
			}
		}
	}
	return out, sc.Err()
}

func parseHash8(s string) *hash8 {
	// Format: $8$<salt>$<crypt-base64-hash>
	parts := strings.SplitN(s, "$", 4)
	if len(parts) != 4 || parts[1] != "8" || parts[2] == "" || parts[3] == "" {
		return nil
	}
	return &hash8{full: s, salt: parts[2], encoded: parts[3]}
}

func crack8(hashes []hash8, wordlistPath string) error {
	wf, err := os.Open(wordlistPath)
	if err != nil {
		return fmt.Errorf("open wordlist: %w", err)
	}
	defer wf.Close()

	fmt.Printf("\nCracking with: %s\n", wordlistPath)

	cracked := make([]string, len(hashes))
	done := 0
	tried := 0

	sc := bufio.NewScanner(wf)
	for sc.Scan() {
		if done == len(hashes) {
			break
		}
		word := strings.TrimRight(sc.Text(), "\r")
		tried++

		for i, h := range hashes {
			if cracked[i] != "" {
				continue
			}
			if type8Match([]byte(word), []byte(h.salt), h.encoded) {
				cracked[i] = word
				done++
				fmt.Printf("\n[+] Hash #%d (%s) cracked: \x1b[32m%q\x1b[0m\n", i+1, h.context, word)
			}
		}

		if tried%100_000 == 0 {
			fmt.Fprintf(os.Stderr, "%d passwords tried...\n", tried)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read wordlist: %w", err)
	}

	fmt.Printf("\nTried: %d  Cracked: %d/%d\n", tried, done, len(hashes))
	if done < len(hashes) {
		fmt.Printf("[-] %d hash(es) not cracked\n", len(hashes)-done)
	}
	return nil
}

// type8Match computes PBKDF2 and compares against the stored crypt base64 hash.
// SHA variant is auto-detected from the encoded hash length:
//
//	27 chars → PBKDF2-HMAC-SHA1   (20-byte output)
//	43 chars → PBKDF2-HMAC-SHA256 (32-byte output)  ← standard Cisco $8$
//	86 chars → PBKDF2-HMAC-SHA512 (64-byte output)
func type8Match(password, salt []byte, encoded string) bool {
	var newHash func() hash.Hash
	var keyLen int

	switch len(encoded) {
	case 27:
		newHash, keyLen = sha1.New, 20
	case 43:
		newHash, keyLen = sha256.New, 32
	case 86:
		newHash, keyLen = sha512.New, 64
	default:
		return false
	}

	dk := pbkdf2Key(password, salt, 20000, keyLen, newHash)
	return cryptB64Encode(dk) == encoded
}

// cryptB64Encode encodes raw bytes using crypt base64.
// Bit packing: MSB-first (same as standard base64) with the crypt alphabet ./0-9A-Za-z.
func cryptB64Encode(b []byte) string {
	const alpha = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	out := make([]byte, 0, ((len(b)+2)/3)*4)
	i := 0
	for ; i+3 <= len(b); i += 3 {
		v := uint32(b[i])<<16 | uint32(b[i+1])<<8 | uint32(b[i+2])
		out = append(out,
			alpha[(v>>18)&0x3f],
			alpha[(v>>12)&0x3f],
			alpha[(v>>6)&0x3f],
			alpha[v&0x3f])
	}
	rem := len(b) - i
	if rem == 2 {
		v := uint32(b[i])<<16 | uint32(b[i+1])<<8
		out = append(out,
			alpha[(v>>18)&0x3f],
			alpha[(v>>12)&0x3f],
			alpha[(v>>6)&0x3f])
	} else if rem == 1 {
		v := uint32(b[i]) << 16
		out = append(out,
			alpha[(v>>18)&0x3f],
			alpha[(v>>12)&0x3f])
	}
	return string(out)
}

// pbkdf2Key derives a key using PBKDF2 with the given hash constructor.
func pbkdf2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	var blockNum [4]byte

	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(blockNum[:], uint32(block))
		prf.Write(blockNum[:])
		U = prf.Sum(U[:0])

		T := make([]byte, hashLen)
		copy(T, U)

		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = prf.Sum(U[:0])
			for j := range T {
				T[j] ^= U[j]
			}
		}
		dk = append(dk, T...)
	}
	return dk[:keyLen]
}
