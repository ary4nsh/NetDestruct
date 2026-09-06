package routing

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Route is a destination prefix to inject.
type Route struct {
	Addr      net.IP
	PrefixLen int
}

// ExpandTargets parses domains, single IPs, CIDRs, comma lists, and IPv4 last-octet ranges.
func ExpandTargets(spec string) ([]Route, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty target spec")
	}
	var out []Route
	seen := make(map[string]bool)
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		routes, err := parseTargetPart(part)
		if err != nil {
			return nil, err
		}
		for _, r := range routes {
			key := fmt.Sprintf("%s/%d", r.Addr, r.PrefixLen)
			if !seen[key] {
				seen[key] = true
				out = append(out, r)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no targets resolved from %q", spec)
	}
	return out, nil
}

func parseTargetPart(part string) ([]Route, error) {
	if strings.Contains(part, "/") {
		return cidrRoutes(part)
	}
	if strings.Count(part, "-") == 1 && strings.Count(part, ".") >= 3 {
		if routes, err := ipv4LastOctetRange(part); err == nil {
			return routes, nil
		}
	}
	if ip := net.ParseIP(part); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return []Route{{Addr: v4, PrefixLen: 32}}, nil
		}
		return []Route{{Addr: ip.To16(), PrefixLen: 128}}, nil
	}
	addrs, err := net.LookupIP(part)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", part, err)
	}
	var routes []Route
	for _, ip := range addrs {
		if v4 := ip.To4(); v4 != nil {
			routes = append(routes, Route{Addr: v4, PrefixLen: 32})
		} else {
			routes = append(routes, Route{Addr: ip.To16(), PrefixLen: 128})
		}
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", part)
	}
	return routes, nil
}

func ipv4LastOctetRange(s string) ([]Route, error) {
	dash := strings.LastIndex(s, "-")
	start := net.ParseIP(strings.TrimSpace(s[:dash]))
	if start == nil || start.To4() == nil {
		return nil, fmt.Errorf("invalid ipv4 range %q", s)
	}
	endOctet, err := strconv.Atoi(strings.TrimSpace(s[dash+1:]))
	if err != nil || endOctet < 0 || endOctet > 255 {
		return nil, fmt.Errorf("invalid ipv4 range %q", s)
	}
	start4 := start.To4()
	if int(start4[3]) > endOctet {
		return nil, fmt.Errorf("invalid ipv4 range %q", s)
	}
	out := make([]Route, 0, endOctet-int(start4[3])+1)
	for o := int(start4[3]); o <= endOctet; o++ {
		ip := append(net.IP{}, start4...)
		ip[3] = byte(o)
		out = append(out, Route{Addr: ip, PrefixLen: 32})
	}
	return out, nil
}

func cidrRoutes(cidr string) ([]Route, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	ones, bits := ipNet.Mask.Size()
	network := ip.Mask(ipNet.Mask)
	if v4 := network.To4(); v4 != nil && bits == 32 {
		if ones > 30 {
			return nil, fmt.Errorf("CIDR %q too small for injection", cidr)
		}
		return []Route{{Addr: v4, PrefixLen: ones}}, nil
	}
	if bits != 128 {
		return nil, fmt.Errorf("unexpected CIDR %q", cidr)
	}
	if ones < 112 {
		return nil, fmt.Errorf("IPv6 CIDR %q too large; max /112", cidr)
	}
	return []Route{{Addr: network.To16(), PrefixLen: ones}}, nil
}

// PrefixMask returns an IPv4 dotted-decimal mask for OSPF external LSAs.
func PrefixMask(prefixLen int) net.IP {
	if prefixLen <= 0 || prefixLen > 32 {
		return net.IPv4(255, 255, 255, 255)
	}
	mask := uint32(0xffffffff) << uint(32-prefixLen)
	b := make(net.IP, 4)
	binary.BigEndian.PutUint32(b, mask)
	return b
}

// EigrpIPv4Bytes encodes a destination for EIGRP internal/external route TLVs.
func EigrpIPv4Bytes(ip net.IP, prefixLen int) []byte {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	switch {
	case prefixLen <= 8:
		return []byte{v4[0]}
	case prefixLen <= 16:
		return v4[:2]
	case prefixLen <= 24:
		return v4[:3]
	default:
		return v4[:4]
	}
}

// EigrpIPv6Bytes encodes a destination for EIGRPv6 external route TLVs.
func EigrpIPv6Bytes(ip net.IP, prefixLen int) []byte {
	v6 := ip.To16()
	if v6 == nil {
		return nil
	}
	byteLen := (prefixLen + 7) / 8
	if byteLen < 1 {
		byteLen = 1
	}
	if byteLen > 16 {
		byteLen = 16
	}
	return v6[:byteLen]
}

// IPv4ToUint32 converts an IPv4 address to uint32.
func IPv4ToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

// Uint32ToIPv4 converts uint32 to IPv4.
func Uint32ToIPv4(v uint32) net.IP {
	b := make(net.IP, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}
