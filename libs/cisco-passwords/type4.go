package ciscopass

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/bits"
	"os"
	"regexp"
	"strings"
)

// Cisco Type 4: raw SHA hash of the password encoded in crypt base64 (./0-9A-Za-z, MSB-first).
// Standard Cisco IOS uses SHA-256 (43-char encoded hash). Hash length identifies the variant:
//   27  → SHA-1    (20-byte output)
//   38  → SHA-224  (28-byte output)
//   43  → SHA-256 or SHA3-256 (32-byte output; both are tried)
//   64  → SHA-384  (48-byte output)
//   86  → SHA-512  (64-byte output)

const cisco4Tag = "$cisco4$"

type hash4 struct {
	context string
	full    string
	encoded string
}

var (
	reEnable4   = regexp.MustCompile(`enable\s+secret\s+(?:\d+\s+)?4\s+(\S+)`)
	reUsername4 = regexp.MustCompile(`username\s+(\S+)\s+(?:privilege\s+\d+\s+)?secret\s+4\s+(\S+)`)
)

func (c *Cracker) runType4() error {
	if c.Wordlist == "" {
		return fmt.Errorf("--type4 requires --wordlist")
	}

	var hashes []hash4
	if c.HashValue != "" {
		h := parseHash4(c.HashValue)
		if h == nil {
			return fmt.Errorf("invalid Type 4 hash: %q", c.HashValue)
		}
		h.context = "direct hash"
		hashes = []hash4{*h}
	} else {
		var err error
		hashes, err = parseConfig4(c.ConfigFile)
		if err != nil {
			return err
		}
		if len(hashes) == 0 {
			fmt.Println("No Type 4 hashes found in config file.")
			return nil
		}
	}

	fmt.Printf("Found %d Type 4 hash(es):\n", len(hashes))
	for i, h := range hashes {
		fmt.Printf("\n=== Type 4 Hash #%d ===\n", i+1)
		fmt.Printf("- Context: %s\n", h.context)
		fmt.Printf("- Hash:    %s\n", h.encoded)
		fmt.Printf("- SHA:     %s\n", sha4VariantName(h.encoded))
	}

	return crack4(hashes, c.Wordlist)
}

func sha4VariantName(encoded string) string {
	switch len(encoded) {
	case 27:
		return "SHA-1"
	case 38:
		return "SHA-224"
	case 43:
		return "SHA-256 / SHA3-256"
	case 64:
		return "SHA-384"
	case 86:
		return "SHA-512"
	default:
		return "unknown"
	}
}

func parseConfig4(path string) ([]hash4, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var out []hash4
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if m := reEnable4.FindStringSubmatch(line); m != nil {
			if h := parseHash4(m[1]); h != nil {
				h.context = "enable secret"
				out = append(out, *h)
			}
		} else if m := reUsername4.FindStringSubmatch(line); m != nil {
			if h := parseHash4(m[2]); h != nil {
				h.context = "username " + m[1]
				out = append(out, *h)
			}
		}
	}
	return out, sc.Err()
}

func parseHash4(s string) *hash4 {
	enc := s
	if strings.HasPrefix(s, cisco4Tag) {
		enc = s[len(cisco4Tag):]
	}
	switch len(enc) {
	case 27, 38, 43, 64, 86:
		return &hash4{full: s, encoded: enc}
	}
	return nil
}

func crack4(hashes []hash4, wordlistPath string) error {
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
			if type4Match([]byte(word), h.encoded) {
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

// type4Match hashes password with all SHA variants matching the encoded length.
func type4Match(password []byte, encoded string) bool {
	switch len(encoded) {
	case 27: // SHA-1: 20 bytes
		h := sha1.Sum(password)
		return cryptB64Encode(h[:]) == encoded
	case 38: // SHA-224: 28 bytes
		h := sha256.Sum224(password)
		return cryptB64Encode(h[:]) == encoded
	case 43: // SHA-256 or SHA3-256: both produce 32 bytes
		h256 := sha256.Sum256(password)
		if cryptB64Encode(h256[:]) == encoded {
			return true
		}
		h3 := sha3_256(password)
		return cryptB64Encode(h3[:]) == encoded
	case 64: // SHA-384: 48 bytes
		h := sha512.Sum384(password)
		return cryptB64Encode(h[:]) == encoded
	case 86: // SHA-512: 64 bytes
		h := sha512.Sum512(password)
		return cryptB64Encode(h[:]) == encoded
	}
	return false
}

// ── SHA3-256 (NIST FIPS 202) implemented via Keccak-f[1600] ──────────────────

// sha3_256 computes SHA3-256 of data (native Go implementation, no x/crypto).
func sha3_256(data []byte) [32]byte {
	const rate = 136 // SHA3-256: (1600 - 2*256) / 8 = 136 bytes per block

	var state [25]uint64

	// Pad: append 0x06 (SHA3 domain), zero-fill to block boundary, set last bit
	padLen := rate - (len(data) % rate)
	buf := make([]byte, len(data)+padLen)
	copy(buf, data)
	buf[len(data)] = 0x06
	buf[len(buf)-1] |= 0x80

	// Absorb each block
	for i := 0; i < len(buf); i += rate {
		for j := 0; j < rate/8; j++ {
			state[j] ^= binary.LittleEndian.Uint64(buf[i+j*8:])
		}
		keccakF1600(&state)
	}

	// Squeeze: first 32 bytes of state
	var out [32]byte
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], state[i])
	}
	return out
}

// keccakRC contains the 24 Keccak-f[1600] round constants.
var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// keccakRho contains rho rotation offsets for each state lane (indexed by x+5*y).
var keccakRho = [25]uint{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

// keccakF1600 applies the Keccak-f[1600] permutation to the 25-word state in place.
func keccakF1600(a *[25]uint64) {
	for round := 0; round < 24; round++ {
		// θ (Theta): mix column parities
		var c [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d := c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
			a[x] ^= d; a[x+5] ^= d; a[x+10] ^= d; a[x+15] ^= d; a[x+20] ^= d
		}

		// ρ (Rho) + π (Pi): rotate and permute lanes
		var b [25]uint64
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				b[y+5*((2*x+3*y)%5)] = bits.RotateLeft64(a[x+5*y], int(keccakRho[x+5*y]))
			}
		}

		// χ (Chi): non-linear mixing
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				a[x+5*y] = b[x+5*y] ^ (^b[(x+1)%5+5*y] & b[(x+2)%5+5*y])
			}
		}

		// ι (Iota): add round constant to lane (0,0)
		a[0] ^= keccakRC[round]
	}
}
