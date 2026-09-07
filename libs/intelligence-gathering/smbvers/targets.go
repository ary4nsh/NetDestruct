package smbvers

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
)

func expandTargets(spec string) ([]net.IP, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty target spec")
	}
	var out []net.IP
	seen := make(map[string]bool)
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ips, err := parseTargetPart(part)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			k := ip.String()
			if !seen[k] {
				seen[k] = true
				out = append(out, ip)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no targets resolved from %q", spec)
	}
	return out, nil
}

func parseTargetPart(part string) ([]net.IP, error) {
	if strings.Contains(part, "/") {
		return cidrTargets(part)
	}
	if strings.Count(part, "-") == 1 && strings.Count(part, ".") >= 3 {
		if ips, err := ipv4LastOctetRange(part); err == nil {
			return ips, nil
		}
	}
	if ip := net.ParseIP(part); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return []net.IP{v4}, nil
		}
		return []net.IP{ip.To16()}, nil
	}
	addrs, err := net.LookupIP(part)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", part, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", part)
	}
	return addrs, nil
}

func ipv4LastOctetRange(s string) ([]net.IP, error) {
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
	out := make([]net.IP, 0, endOctet-int(start4[3])+1)
	for o := int(start4[3]); o <= endOctet; o++ {
		ip := append(net.IP{}, start4...)
		ip[3] = byte(o)
		out = append(out, ip)
	}
	return out, nil
}

func cidrTargets(cidr string) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	if v4 := ip.To4(); v4 != nil {
		ones, bits := ipNet.Mask.Size()
		if bits != 32 {
			return nil, fmt.Errorf("unexpected IPv4 CIDR %q", cidr)
		}
		total := uint32(1) << uint(32-ones)
		if total > 65536 {
			return nil, fmt.Errorf("CIDR %q too large; max 65536 addresses", cidr)
		}
		network := binary.BigEndian.Uint32(v4.Mask(ipNet.Mask))
		out := make([]net.IP, 0, total)
		for i := uint32(0); i < total; i++ {
			addr := make(net.IP, 4)
			binary.BigEndian.PutUint32(addr, network+i)
			out = append(out, addr)
		}
		return out, nil
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 128 {
		return nil, fmt.Errorf("unexpected IPv6 CIDR %q", cidr)
	}
	hostBits := 128 - ones
	if hostBits > 12 {
		return nil, fmt.Errorf("IPv6 CIDR %q too large; max /116", cidr)
	}
	count := 1 << hostBits
	base := new(big.Int).SetBytes(ip.Mask(ipNet.Mask).To16())
	out := make([]net.IP, 0, count)
	for i := 0; i < count; i++ {
		v := new(big.Int).Add(base, big.NewInt(int64(i)))
		b := v.Bytes()
		ip16 := make([]byte, 16)
		copy(ip16[16-len(b):], b)
		out = append(out, net.IP(ip16))
	}
	return out, nil
}
