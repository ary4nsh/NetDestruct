package snmp

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPort    = 161
	defaultTimeout = 1500 * time.Millisecond
	snmpTag        = "\x1b[33m[SNMP]\x1b[0m"
)

// SNMPTag returns the yellow [SNMP] log prefix.
func SNMPTag() string { return snmpTag }

// FormatSNMPValue formats a decoded SNMP value for display.
func FormatSNMPValue(tag byte, raw []byte) string { return formatSNMPValue(tag, raw) }

// Scanner brute-forces SNMP community strings against a target set.
type Scanner struct {
	Target        string
	CommunityFile string
	RateLimitMS   int
}

func (s *Scanner) Run() error {
	if strings.TrimSpace(s.Target) == "" {
		return fmt.Errorf("--snmp requires --target <domain|ip|range>")
	}
	if strings.TrimSpace(s.CommunityFile) == "" {
		return fmt.Errorf("--snmp requires --file <community_file>")
	}

	communities, err := readCommunities(s.CommunityFile)
	if err != nil {
		return err
	}
	if len(communities) == 0 {
		return fmt.Errorf("community file is empty: %s", s.CommunityFile)
	}

	targets, err := expandTargets(s.Target)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no targets resolved from %q", s.Target)
	}

	rate := s.RateLimitMS
	if rate <= 0 {
		rate = 100
	}
	wait := time.Duration(rate) * time.Millisecond

	fmt.Printf("%s Targets: %d  Communities: %d  RateLimit: %dms\n", snmpTag, len(targets), len(communities), rate)
	for _, target := range targets {
		for _, community := range communities {
			if ok, desc, err := probe(target, defaultPort, community); err == nil && ok {
				fmt.Printf("%s %s [%s] %s\n", snmpTag, target.String(), community, desc)
			}
			time.Sleep(wait)
		}
	}
	return nil
}

func probeV2c(ip net.IP, port int, community string) (bool, string, error) {
	if port <= 0 {
		port = defaultPort
	}
	addr := &net.UDPAddr{IP: ip, Port: port}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(defaultTimeout)); err != nil {
		return false, "", err
	}
	reqID := int(time.Now().UnixNano() & 0x7fffffff)
	req := buildGetRequestV2c(community, reqID, oidSysDescr)
	if _, err := conn.Write(req); err != nil {
		return false, "", err
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return false, "", nil
		}
		return false, "", err
	}
	return parseResponse(buf[:n], reqID)
}

func probe(ip net.IP, port int, community string) (bool, string, error) {
	if port <= 0 {
		port = defaultPort
	}
	addr := &net.UDPAddr{IP: ip, Port: port}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(defaultTimeout)); err != nil {
		return false, "", err
	}
	reqID := int(time.Now().UnixNano() & 0x7fffffff)
	req := buildGetRequest(community, reqID)
	if _, err := conn.Write(req); err != nil {
		return false, "", err
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return false, "", nil
		}
		return false, "", err
	}
	ok, desc, err := parseResponse(buf[:n], reqID)
	return ok, desc, err
}

func buildGetRequest(community string, reqID int) []byte {
	oid := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00} // 1.3.6.1.2.1.1.1.0
	nullValue := []byte{0x05, 0x00}
	varBind := asn1Seq(append(oid, nullValue...))
	varBindList := asn1Seq(varBind)
	pduBody := append(append(append(asn1Int(reqID), asn1Int(0)...), asn1Int(0)...), varBindList...)
	getPDU := asn1TLV(0xa0, pduBody)
	msg := append(append(append(asn1Int(0), asn1OctetString([]byte(community))...), getPDU...), []byte{}...)
	return asn1Seq(msg)
}

func parseResponse(b []byte, reqID int) (bool, string, error) {
	i := 0
	if readByte(b, &i) != 0x30 {
		return false, "", fmt.Errorf("invalid snmp packet")
	}
	if _, ok := readLength(b, &i); !ok {
		return false, "", fmt.Errorf("invalid snmp length")
	}
	// Version
	if readByte(b, &i) != 0x02 {
		return false, "", fmt.Errorf("missing snmp version")
	}
	if _, ok := readInt(b, &i); !ok {
		return false, "", fmt.Errorf("invalid snmp version")
	}
	// Community
	if readByte(b, &i) != 0x04 {
		return false, "", fmt.Errorf("missing community")
	}
	if _, ok := readOctets(b, &i); !ok {
		return false, "", fmt.Errorf("invalid community")
	}
	// Response PDU
	if readByte(b, &i) != 0xa2 {
		return false, "", nil
	}
	if _, ok := readLength(b, &i); !ok {
		return false, "", fmt.Errorf("invalid pdu length")
	}
	if readByte(b, &i) != 0x02 {
		return false, "", fmt.Errorf("missing request id")
	}
	gotReqID, ok := readInt(b, &i)
	if !ok {
		return false, "", fmt.Errorf("invalid request id")
	}
	if gotReqID != reqID {
		return false, "", nil
	}
	if readByte(b, &i) != 0x02 {
		return false, "", fmt.Errorf("missing error status")
	}
	errStatus, ok := readInt(b, &i)
	if !ok {
		return false, "", fmt.Errorf("invalid error status")
	}
	if readByte(b, &i) != 0x02 {
		return false, "", fmt.Errorf("missing error index")
	}
	if _, ok := readInt(b, &i); !ok {
		return false, "", fmt.Errorf("invalid error index")
	}
	if errStatus != 0 {
		return false, "", nil
	}
	// VarBindList + first VarBind to extract sysDescr
	if readByte(b, &i) != 0x30 {
		return true, "valid community", nil
	}
	if _, ok := readLength(b, &i); !ok {
		return true, "valid community", nil
	}
	if readByte(b, &i) != 0x30 {
		return true, "valid community", nil
	}
	if _, ok := readLength(b, &i); !ok {
		return true, "valid community", nil
	}
	if readByte(b, &i) != 0x06 {
		return true, "valid community", nil
	}
	if _, ok := readOctets(b, &i); !ok {
		return true, "valid community", nil
	}
	valueType := readByte(b, &i)
	if valueType != 0x04 {
		return true, "valid community", nil
	}
	v, ok := readOctets(b, &i)
	if !ok {
		return true, "valid community", nil
	}
	desc := strings.TrimSpace(string(v))
	if desc == "" {
		desc = "valid community"
	}
	return true, desc, nil
}

func readByte(b []byte, i *int) byte {
	if *i >= len(b) {
		return 0
	}
	v := b[*i]
	*i = *i + 1
	return v
}

func readLength(b []byte, i *int) (int, bool) {
	if *i >= len(b) {
		return 0, false
	}
	first := b[*i]
	*i++
	if first&0x80 == 0 {
		return int(first), true
	}
	n := int(first & 0x7f)
	if n == 0 || n > 4 || *i+n > len(b) {
		return 0, false
	}
	v := 0
	for j := 0; j < n; j++ {
		v = (v << 8) | int(b[*i+j])
	}
	*i += n
	return v, true
}

func readInt(b []byte, i *int) (int, bool) {
	l, ok := readLength(b, i)
	if !ok || l <= 0 || *i+l > len(b) {
		return 0, false
	}
	v := 0
	for j := 0; j < l; j++ {
		v = (v << 8) | int(b[*i+j])
	}
	*i += l
	return v, true
}

func readOctets(b []byte, i *int) ([]byte, bool) {
	l, ok := readLength(b, i)
	if !ok || l < 0 || *i+l > len(b) {
		return nil, false
	}
	v := b[*i : *i+l]
	*i += l
	return v, true
}

func asn1Seq(body []byte) []byte { return asn1TLV(0x30, body) }

func asn1Int(v int) []byte {
	if v == 0 {
		return []byte{0x02, 0x01, 0x00}
	}
	bi := big.NewInt(int64(v)).Bytes()
	if bi[0]&0x80 != 0 {
		bi = append([]byte{0x00}, bi...)
	}
	return asn1TLV(0x02, bi)
}

func asn1OctetString(v []byte) []byte { return asn1TLV(0x04, v) }

func asn1TLV(tag byte, body []byte) []byte {
	out := []byte{tag}
	out = append(out, encodeLength(len(body))...)
	out = append(out, body...)
	return out
}

func encodeLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n <= 0xff {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func readCommunities(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open community file: %w", err)
	}
	defer f.Close()
	var communities []string
	seen := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !seen[line] {
			seen[line] = true
			communities = append(communities, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read community file: %w", err)
	}
	return communities, nil
}

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

// ExpandTargets resolves --target to one or more host addresses: comma lists, CIDR,
// IPv4 last-octet ranges, hostnames, and text files (one address per line).
func ExpandTargets(spec string) ([]net.IP, error) {
	return expandTargets(spec)
}

func parseTargetPart(part string) ([]net.IP, error) {
	if strings.HasPrefix(part, "@") {
		return readTargetFile(strings.TrimSpace(part[1:]))
	}
	if fi, err := os.Stat(part); err == nil && fi.Mode().IsRegular() {
		return readTargetFile(part)
	}
	if strings.Contains(part, "/") {
		return cidrTargets(part)
	}
	if strings.Count(part, "-") == 1 && strings.Count(part, ".") >= 3 {
		if ips, err := ipv4LastOctetRange(part); err == nil {
			return ips, nil
		}
	}
	if ip := net.ParseIP(part); ip != nil {
		return []net.IP{ip}, nil
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

func readTargetFile(path string) ([]net.IP, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("empty target file path")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open target file %q: %w", path, err)
	}
	defer f.Close()

	var out []net.IP
	seen := make(map[string]bool)
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, part := range strings.Split(line, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			ips, err := parseTargetPart(part)
			if err != nil {
				return nil, fmt.Errorf("target file %q line %d: %w", path, lineNo, err)
			}
			for _, ip := range ips {
				k := ip.String()
				if !seen[k] {
					seen[k] = true
					out = append(out, ip)
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read target file %q: %w", path, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("target file %q contains no addresses", path)
	}
	return out, nil
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
