package dns

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func loadSpoofDomains(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	var raw []string
	if strings.Contains(spec, ",") {
		for _, part := range strings.Split(spec, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				raw = append(raw, part)
			}
		}
	} else if st, err := os.Stat(spec); err == nil && !st.IsDir() {
		f, err := os.Open(spec)
		if err != nil {
			return nil, fmt.Errorf("open domain file %q: %w", spec, err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if i := strings.IndexAny(line, "#"); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			if line != "" {
				raw = append(raw, line)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("read domain file %q: %w", spec, err)
		}
	} else {
		raw = []string{spec}
	}

	seen := make(map[string]bool)
	var out []string
	for _, d := range raw {
		d = normalizeDomain(d)
		if d == "" {
			continue
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no domains resolved from %q", spec)
	}
	return out, nil
}

func normalizeDomain(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.TrimSuffix(name, ".")
}

func shouldSpoofQuery(name string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	return matchPattern(normalizeDomain(name), patterns)
}

func matchPattern(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchGlob(name, pattern) {
			return true
		}
	}
	return false
}

// matchGlob implements * and ? wildcards (case-insensitive).
func matchGlob(s, pattern string) bool {
	s = normalizeDomain(s)
	pattern = normalizeDomain(pattern)
	return matchGlobRec(s, pattern)
}

func matchGlobRec(s, pattern string) bool {
	for {
		if pattern == "" {
			return s == ""
		}
		if pattern[0] == '*' {
			pattern = pattern[1:]
			if pattern == "" {
				return true
			}
			if pattern[0] != '?' && pattern[0] != '*' {
				for i := 0; i < len(s); i++ {
					if s[i] == pattern[0] && matchGlobRec(s[i+1:], pattern[1:]) {
						return true
					}
				}
				return false
			}
			for i := 0; i <= len(s); i++ {
				if matchGlobRec(s[i:], pattern) {
					return true
				}
			}
			return false
		}
		if s == "" {
			return false
		}
		if pattern[0] != '?' && pattern[0] != s[0] {
			return false
		}
		s = s[1:]
		pattern = pattern[1:]
	}
}
