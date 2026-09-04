package ciscopass

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// xlat is the fixed 53-byte XOR key table used by Cisco Type 7.
// The cipher wraps at index 51 (only indices 0-50 are ever used).
var xlat = [53]byte{
	0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e, 0x69, 0x79,
	0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53, 0x55, 0x42,
	0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39, 0x38, 0x33, 0x34, 0x6e, 0x63, 0x78,
	0x76, 0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38,
	0x37,
}

type pass7 struct {
	context   string
	encrypted string
	decrypted string
}

// Broad pattern: catches any Cisco config line that contains (password|secret) 7 <hex>.
// This covers enable password/secret, username password, line vty password,
// ip ftp password, snmp-server password, etc.
var reAnyType7 = regexp.MustCompile(`(?i)(?:password|secret)\s+7\s+([0-9A-Fa-f]{4,})`)

var reUsername7ctx = regexp.MustCompile(`(?i)username\s+(\S+)`)

func (c *Cracker) runType7() error {
	if c.HashValue != "" {
		dec, err := decryptType7(c.HashValue)
		if err != nil {
			return fmt.Errorf("decrypt Type 7: %w", err)
		}
		fmt.Printf("=== Type 7 Decrypt ===\n")
		fmt.Printf("- Encrypted: %s\n", strings.ToUpper(c.HashValue))
		fmt.Printf("- Decrypted: \x1b[32m%q\x1b[0m\n", dec)
		return nil
	}

	passwords, err := parseConfig7(c.ConfigFile)
	if err != nil {
		return err
	}

	if len(passwords) == 0 {
		fmt.Println("No Type 7 passwords found in config file.")
		return nil
	}

	fmt.Printf("Found %d Type 7 password(s):\n", len(passwords))
	decrypted := 0
	for i, p := range passwords {
		fmt.Printf("\n=== Type 7 Password #%d ===\n", i+1)
		fmt.Printf("- Context:   %s\n", p.context)
		fmt.Printf("- Encrypted: %s\n", p.encrypted)
		if p.decrypted != "" {
			fmt.Printf("- Decrypted: \x1b[32m%q\x1b[0m\n", p.decrypted)
			decrypted++
		} else {
			fmt.Printf("- Decrypted: (failed)\n")
		}
	}

	fmt.Printf("\nDecrypted: %d/%d\n", decrypted, len(passwords))
	return nil
}

func parseConfig7(path string) ([]pass7, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var out []pass7
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		m := reAnyType7.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		enc := m[1]
		ctx := extractContext7(line)
		dec, err := decryptType7(enc)
		p := pass7{
			context:   ctx,
			encrypted: strings.ToUpper(enc),
		}
		if err == nil {
			p.decrypted = dec
		}
		out = append(out, p)
	}
	return out, sc.Err()
}

func extractContext7(line string) string {
	trimmed := strings.TrimSpace(line)
	lower := strings.ToLower(trimmed)
	switch {
	case strings.HasPrefix(lower, "enable secret"):
		return "enable secret"
	case strings.HasPrefix(lower, "enable password"):
		return "enable password"
	default:
		if m := reUsername7ctx.FindStringSubmatch(trimmed); m != nil {
			return "username " + m[1]
		}
		return "password"
	}
}

// decryptType7 reverses the Cisco Type 7 XOR cipher.
// Format: first 2 decimal digits = xlat start index (0-50), rest = hex-encoded ciphertext.
func decryptType7(ep string) (string, error) {
	ep = strings.TrimSpace(ep)
	if len(ep) < 4 || len(ep)%2 != 0 {
		return "", fmt.Errorf("invalid ciphertext length")
	}
	s, err := strconv.Atoi(ep[:2])
	if err != nil || s < 0 || s > 50 {
		return "", fmt.Errorf("invalid salt %q", ep[:2])
	}
	rest := ep[2:]
	var plain strings.Builder
	for i := 0; i < len(rest); i += 2 {
		v, err := strconv.ParseUint(rest[i:i+2], 16, 8)
		if err != nil {
			return "", fmt.Errorf("invalid hex byte at position %d", i)
		}
		plain.WriteByte(byte(v) ^ xlat[s])
		s++
		if s == 51 {
			s = 0
		}
	}
	return plain.String(), nil
}
