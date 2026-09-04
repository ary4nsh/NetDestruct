package ciscopass

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

type Cracker struct {
	ConfigFile string
	HashValue  string
	Type4      bool
	Type5      bool
	Type7      bool
	Type8      bool
	Type9      bool
	Wordlist   string
}

type hash5 struct {
	context string
	full    string
	salt    string
}

var (
	reEnable5   = regexp.MustCompile(`enable\s+secret\s+(?:\d+\s+)?5\s+(\$1\$\S+)`)
	reUsername5 = regexp.MustCompile(`username\s+(\S+)\s+(?:privilege\s+\d+\s+)?secret\s+5\s+(\$1\$\S+)`)
)

func (c *Cracker) Run() error {
	switch {
	case c.Type4:
		return c.runType4()
	case c.Type5:
		return c.runType5()
	case c.Type7:
		return c.runType7()
	case c.Type8:
		return c.runType8()
	case c.Type9:
		return c.runType9()
	default:
		return fmt.Errorf("specify --type4, --type5, --type7, --type8, or --type9")
	}
}

func (c *Cracker) runType5() error {
	if c.Wordlist == "" {
		return fmt.Errorf("--type5 requires --wordlist")
	}

	var hashes []hash5
	if c.HashValue != "" {
		h := parseHash5(c.HashValue)
		if h == nil {
			return fmt.Errorf("invalid Type 5 hash: %q (expected $1$salt$hash)", c.HashValue)
		}
		h.context = "direct hash"
		hashes = []hash5{*h}
	} else {
		var err error
		hashes, err = parseConfig5(c.ConfigFile)
		if err != nil {
			return err
		}
		if len(hashes) == 0 {
			fmt.Println("No Type 5 hashes found in config file.")
			return nil
		}
	}

	fmt.Printf("Found %d Type 5 hash(es):\n", len(hashes))
	for i, h := range hashes {
		fmt.Printf("\n=== Type 5 Hash #%d ===\n", i+1)
		fmt.Printf("- Context: %s\n", h.context)
		fmt.Printf("- Hash:    %s\n", h.full)
		fmt.Printf("- Salt:    %s\n", h.salt)
	}

	return crack5(hashes, c.Wordlist)
}

func parseConfig5(path string) ([]hash5, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var out []hash5
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if m := reEnable5.FindStringSubmatch(line); m != nil {
			if h := parseHash5(m[1]); h != nil {
				h.context = "enable secret"
				out = append(out, *h)
			}
		} else if m := reUsername5.FindStringSubmatch(line); m != nil {
			if h := parseHash5(m[2]); h != nil {
				h.context = "username " + m[1]
				out = append(out, *h)
			}
		}
	}
	return out, sc.Err()
}

func parseHash5(s string) *hash5 {
	parts := strings.SplitN(s, "$", 4)
	if len(parts) != 4 || parts[1] != "1" || parts[2] == "" {
		return nil
	}
	return &hash5{full: s, salt: parts[2]}
}

func crack5(hashes []hash5, wordlistPath string) error {
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
			if md5cryptHash([]byte(word), []byte(h.salt)) == h.full {
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

// md5cryptHash computes the Cisco Type 5 / Unix md5crypt ($1$) hash.
// Algorithm from the original FreeBSD md5crypt implementation.
func md5cryptHash(password, salt []byte) string {
	const magic = "$1$"

	alt := md5.New()
	alt.Write(password)
	alt.Write(salt)
	alt.Write(password)
	altSum := alt.Sum(nil)

	ctx := md5.New()
	ctx.Write(password)
	ctx.Write([]byte(magic))
	ctx.Write(salt)

	for i := len(password); i > 0; i -= 16 {
		n := 16
		if i < n {
			n = i
		}
		ctx.Write(altSum[:n])
	}

	for i := len(password); i > 0; i >>= 1 {
		if i&1 != 0 {
			ctx.Write([]byte{0x00})
		} else {
			ctx.Write(password[:1])
		}
	}

	digest := ctx.Sum(nil)

	for i := 0; i < 1000; i++ {
		c := md5.New()
		if i&1 != 0 {
			c.Write(password)
		} else {
			c.Write(digest)
		}
		if i%3 != 0 {
			c.Write(salt)
		}
		if i%7 != 0 {
			c.Write(password)
		}
		if i&1 != 0 {
			c.Write(digest)
		} else {
			c.Write(password)
		}
		digest = c.Sum(nil)
	}

	var sb strings.Builder
	sb.WriteString(magic)
	sb.Write(salt)
	sb.WriteByte('$')
	sb.WriteString(to64(uint(digest[0])<<16|uint(digest[6])<<8|uint(digest[12]), 4))
	sb.WriteString(to64(uint(digest[1])<<16|uint(digest[7])<<8|uint(digest[13]), 4))
	sb.WriteString(to64(uint(digest[2])<<16|uint(digest[8])<<8|uint(digest[14]), 4))
	sb.WriteString(to64(uint(digest[3])<<16|uint(digest[9])<<8|uint(digest[15]), 4))
	sb.WriteString(to64(uint(digest[4])<<16|uint(digest[10])<<8|uint(digest[5]), 4))
	sb.WriteString(to64(uint(digest[11]), 2))
	return sb.String()
}

func to64(v uint, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = itoa64[v&0x3f]
		v >>= 6
	}
	return string(b)
}
