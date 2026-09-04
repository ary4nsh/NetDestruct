package ciscopass

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/bits"
	"os"
	"regexp"
	"strings"
)

type hash9 struct {
	context string
	full    string
	salt    string
	encoded string
}

var (
	reEnable9   = regexp.MustCompile(`enable\s+secret\s+(?:\d+\s+)?9\s+(\$9\$\S+)`)
	reUsername9 = regexp.MustCompile(`username\s+(\S+)\s+(?:privilege\s+\d+\s+)?secret\s+9\s+(\$9\$\S+)`)
)

func (c *Cracker) runType9() error {
	if c.Wordlist == "" {
		return fmt.Errorf("--type9 requires --wordlist")
	}

	var hashes []hash9
	if c.HashValue != "" {
		h := parseHash9(c.HashValue)
		if h == nil {
			return fmt.Errorf("invalid Type 9 hash: %q (expected $9$salt$hash)", c.HashValue)
		}
		h.context = "direct hash"
		hashes = []hash9{*h}
	} else {
		var err error
		hashes, err = parseConfig9(c.ConfigFile)
		if err != nil {
			return err
		}
		if len(hashes) == 0 {
			fmt.Println("No Type 9 hashes found in config file.")
			return nil
		}
	}

	fmt.Printf("Found %d Type 9 hash(es):\n", len(hashes))
	for i, h := range hashes {
		fmt.Printf("\n=== Type 9 Hash #%d ===\n", i+1)
		fmt.Printf("- Context: %s\n", h.context)
		fmt.Printf("- Hash:    %s\n", h.full)
		fmt.Printf("- Salt:    %s\n", h.salt)
	}

	return crack9(hashes, c.Wordlist)
}

func parseConfig9(path string) ([]hash9, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var out []hash9
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if m := reEnable9.FindStringSubmatch(line); m != nil {
			if h := parseHash9(m[1]); h != nil {
				h.context = "enable secret"
				out = append(out, *h)
			}
		} else if m := reUsername9.FindStringSubmatch(line); m != nil {
			if h := parseHash9(m[2]); h != nil {
				h.context = "username " + m[1]
				out = append(out, *h)
			}
		}
	}
	return out, sc.Err()
}

func parseHash9(s string) *hash9 {
	// Format: $9$<salt>$<43-char-crypt-base64-hash>
	parts := strings.SplitN(s, "$", 4)
	if len(parts) != 4 || parts[1] != "9" || parts[2] == "" || parts[3] == "" {
		return nil
	}
	return &hash9{full: s, salt: parts[2], encoded: parts[3]}
}

func crack9(hashes []hash9, wordlistPath string) error {
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
			// scrypt N=16384 r=1 p=1 — ~2MB RAM and ~65K Salsa rounds per candidate
			dk := scryptKey([]byte(word), []byte(h.salt), 16384, 1, 1, 32)
			if cryptB64Encode(dk) == h.encoded {
				cracked[i] = word
				done++
				fmt.Printf("\n[+] Hash #%d (%s) cracked: \x1b[32m%q\x1b[0m\n", i+1, h.context, word)
			}
		}

		if tried%100 == 0 {
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

// scryptKey implements RFC 7914 scrypt key derivation.
// For Cisco Type 9: N=16384, r=1, p=1, keyLen=32.
func scryptKey(password, salt []byte, N, r, p, keyLen int) []byte {
	blockSize := 128 * r

	// Phase 1: PBKDF2-SHA256(password, salt, 1, p*blockSize)
	B := pbkdf2Key(password, salt, 1, p*blockSize, sha256.New)

	// Phase 2: ROMix each of the p blocks
	for i := 0; i < p; i++ {
		scryptROMix(B[i*blockSize:(i+1)*blockSize], r, N)
	}

	// Phase 3: PBKDF2-SHA256(password, B, 1, keyLen)
	return pbkdf2Key(password, B, 1, keyLen, sha256.New)
}

// scryptROMix applies the ROMix function to a 128*r byte block in place (RFC 7914 §5).
func scryptROMix(B []byte, r, N int) {
	blockSize := 128 * r
	X := make([]byte, blockSize)
	copy(X, B)

	// Fill V: V[i] = X, then X = BlockMix(X)
	V := make([]byte, N*blockSize)
	for i := 0; i < N; i++ {
		copy(V[i*blockSize:], X)
		scryptBlockMix(X, r)
	}

	// Mix phase
	for i := 0; i < N; i++ {
		// Integerify: first 8 bytes of last 64-byte block, little-endian
		j := int(binary.LittleEndian.Uint64(X[(2*r-1)*64:]) % uint64(N))
		xorBytes(X, V[j*blockSize:(j+1)*blockSize])
		scryptBlockMix(X, r)
	}

	copy(B, X)
}

// scryptBlockMix applies the BlockMix function in place (RFC 7914 §4).
func scryptBlockMix(B []byte, r int) {
	n := 2 * r
	Y := make([]byte, len(B))

	// X = last 64-byte block
	X := make([]byte, 64)
	copy(X, B[(n-1)*64:])

	for i := 0; i < n; i++ {
		xorBytes(X, B[i*64:(i+1)*64])
		salsa20_8(X)
		copy(Y[i*64:], X)
	}

	// Output: even-indexed blocks first, then odd-indexed
	for i := 0; i < r; i++ {
		copy(B[i*64:], Y[2*i*64:])
	}
	for i := 0; i < r; i++ {
		copy(B[(r+i)*64:], Y[(2*i+1)*64:])
	}
}

func xorBytes(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// salsa20_8 applies the Salsa20/8 core to a 64-byte block in place (RFC 7914 §3).
// Four double-rounds (column + row), then add original state.
func salsa20_8(B []byte) {
	x0 := binary.LittleEndian.Uint32(B[0:])
	x1 := binary.LittleEndian.Uint32(B[4:])
	x2 := binary.LittleEndian.Uint32(B[8:])
	x3 := binary.LittleEndian.Uint32(B[12:])
	x4 := binary.LittleEndian.Uint32(B[16:])
	x5 := binary.LittleEndian.Uint32(B[20:])
	x6 := binary.LittleEndian.Uint32(B[24:])
	x7 := binary.LittleEndian.Uint32(B[28:])
	x8 := binary.LittleEndian.Uint32(B[32:])
	x9 := binary.LittleEndian.Uint32(B[36:])
	x10 := binary.LittleEndian.Uint32(B[40:])
	x11 := binary.LittleEndian.Uint32(B[44:])
	x12 := binary.LittleEndian.Uint32(B[48:])
	x13 := binary.LittleEndian.Uint32(B[52:])
	x14 := binary.LittleEndian.Uint32(B[56:])
	x15 := binary.LittleEndian.Uint32(B[60:])

	z0, z1, z2, z3 := x0, x1, x2, x3
	z4, z5, z6, z7 := x4, x5, x6, x7
	z8, z9, z10, z11 := x8, x9, x10, x11
	z12, z13, z14, z15 := x12, x13, x14, x15

	for i := 0; i < 4; i++ {
		// Column rounds
		z4 ^= bits.RotateLeft32(z0+z12, 7)
		z8 ^= bits.RotateLeft32(z4+z0, 9)
		z12 ^= bits.RotateLeft32(z8+z4, 13)
		z0 ^= bits.RotateLeft32(z12+z8, 18)

		z9 ^= bits.RotateLeft32(z5+z1, 7)
		z13 ^= bits.RotateLeft32(z9+z5, 9)
		z1 ^= bits.RotateLeft32(z13+z9, 13)
		z5 ^= bits.RotateLeft32(z1+z13, 18)

		z14 ^= bits.RotateLeft32(z10+z6, 7)
		z2 ^= bits.RotateLeft32(z14+z10, 9)
		z6 ^= bits.RotateLeft32(z2+z14, 13)
		z10 ^= bits.RotateLeft32(z6+z2, 18)

		z3 ^= bits.RotateLeft32(z15+z11, 7)
		z7 ^= bits.RotateLeft32(z3+z15, 9)
		z11 ^= bits.RotateLeft32(z7+z3, 13)
		z15 ^= bits.RotateLeft32(z11+z7, 18)

		// Row rounds
		z1 ^= bits.RotateLeft32(z0+z3, 7)
		z2 ^= bits.RotateLeft32(z1+z0, 9)
		z3 ^= bits.RotateLeft32(z2+z1, 13)
		z0 ^= bits.RotateLeft32(z3+z2, 18)

		z6 ^= bits.RotateLeft32(z5+z4, 7)
		z7 ^= bits.RotateLeft32(z6+z5, 9)
		z4 ^= bits.RotateLeft32(z7+z6, 13)
		z5 ^= bits.RotateLeft32(z4+z7, 18)

		z11 ^= bits.RotateLeft32(z10+z9, 7)
		z8 ^= bits.RotateLeft32(z11+z10, 9)
		z9 ^= bits.RotateLeft32(z8+z11, 13)
		z10 ^= bits.RotateLeft32(z9+z8, 18)

		z12 ^= bits.RotateLeft32(z15+z14, 7)
		z13 ^= bits.RotateLeft32(z12+z15, 9)
		z14 ^= bits.RotateLeft32(z13+z12, 13)
		z15 ^= bits.RotateLeft32(z14+z13, 18)
	}

	binary.LittleEndian.PutUint32(B[0:], z0+x0)
	binary.LittleEndian.PutUint32(B[4:], z1+x1)
	binary.LittleEndian.PutUint32(B[8:], z2+x2)
	binary.LittleEndian.PutUint32(B[12:], z3+x3)
	binary.LittleEndian.PutUint32(B[16:], z4+x4)
	binary.LittleEndian.PutUint32(B[20:], z5+x5)
	binary.LittleEndian.PutUint32(B[24:], z6+x6)
	binary.LittleEndian.PutUint32(B[28:], z7+x7)
	binary.LittleEndian.PutUint32(B[32:], z8+x8)
	binary.LittleEndian.PutUint32(B[36:], z9+x9)
	binary.LittleEndian.PutUint32(B[40:], z10+x10)
	binary.LittleEndian.PutUint32(B[44:], z11+x11)
	binary.LittleEndian.PutUint32(B[48:], z12+x12)
	binary.LittleEndian.PutUint32(B[52:], z13+x13)
	binary.LittleEndian.PutUint32(B[56:], z14+x14)
	binary.LittleEndian.PutUint32(B[60:], z15+x15)
}
