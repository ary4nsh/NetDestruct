package snmp

import (
	"fmt"
	"strconv"
	"strings"
)

// defaultWalkRoot is snmpwalk's default subtree (1.3.6.1.2.1 / mib-2).
var defaultWalkRoot = []int{1, 3, 6, 1, 2, 1}

// parseOIDList splits comma-separated numeric OID strings.
func parseOIDList(spec string) ([][]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return [][]int{append([]int(nil), defaultWalkRoot...)}, nil
	}
	var out [][]int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		oid, err := parseOID(part)
		if err != nil {
			return nil, err
		}
		out = append(out, oid)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no OIDs in %q", spec)
	}
	return out, nil
}

func parseOID(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, ".")
	if s == "" {
		return nil, fmt.Errorf("empty OID")
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("invalid OID %q", s)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OID component %q in %q", p, s)
		}
		out = append(out, n)
	}
	if len(out) < 2 {
		return nil, fmt.Errorf("OID must have at least two components: %q", s)
	}
	return out, nil
}

func formatOID(oid []int) string {
	if len(oid) == 0 {
		return "."
	}
	var b strings.Builder
	b.WriteByte('.')
	for i, c := range oid {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.Itoa(c))
	}
	return b.String()
}

func encodeOID(oid []int) []byte {
	if len(oid) < 2 {
		panic("encodeOID: need >= 2 components")
	}
	body := []byte{byte(40*oid[0] + oid[1])}
	for _, c := range oid[2:] {
		body = append(body, encodeBase128(uint64(c))...)
	}
	return asn1TLV(0x06, body)
}

func encodeBase128(v uint64) []byte {
	if v == 0 {
		return []byte{0}
	}
	var stack [5]byte
	n := 0
	for v > 0 {
		stack[n] = byte(v & 0x7f)
		v >>= 7
		n++
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		b := stack[n-1-i]
		if i < n-1 {
			b |= 0x80
		}
		out[i] = b
	}
	return out
}

func decodeOID(raw []byte) ([]int, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty OID encoding")
	}
	first := int(raw[0])
	out := []int{first / 40, first % 40}
	i := 1
	for i < len(raw) {
		var v uint64
		for i < len(raw) {
			b := raw[i]
			i++
			v = (v << 7) | uint64(b&0x7f)
			if b&0x80 == 0 {
				break
			}
		}
		out = append(out, int(v))
	}
	return out, nil
}

// oidCompare returns -1, 0, or 1 (lexicographic on components).
func oidCompare(a, b []int) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// oidEndBound returns the snmpwalk end OID: root with last component incremented.
func oidEndBound(root []int) []int {
	end := append([]int(nil), root...)
	end[len(end)-1]++
	return end
}
