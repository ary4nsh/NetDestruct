package ftp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// BounceScanner probes FTP servers for PORT-command bounce and
// scans target ports through a vulnerable relay.
type BounceScanner struct {
	CredServer string // user:password@host <target-ip>
	Ports      []int  // destination ports on target (--port); optional for capability-only check
	FTPSPort   int    // FTP control port when host has no :port (default 21)
}

// PortState is the inferred state of a bounced port probe.
type PortState int

const (
	PortUnknown PortState = iota
	PortOpen
	PortClosed
	PortFiltered
	PortBounceDenied
)

func (s PortState) String() string {
	switch s {
	case PortOpen:
		return "open"
	case PortClosed:
		return "closed"
	case PortFiltered:
		return "filtered"
	case PortBounceDenied:
		return "bounce-denied"
	default:
		return "unknown"
	}
}

// Run tests each FTP host for bounce capability and optionally scans target ports.
func (b *BounceScanner) Run() error {
	user, pass, hostSpec, targetStr, err := parseBounceSpec(b.CredServer)
	if err != nil {
		return err
	}
	if host, p, splitErr := net.SplitHostPort(hostSpec); splitErr == nil {
		hostSpec = host
		if portNum, err := strconv.Atoi(p); err == nil && portNum > 0 {
			b.FTPSPort = portNum
		}
	}
	target, targetDisplay, err := resolveBounceTarget(targetStr)
	if err != nil {
		return err
	}

	hosts, err := expandFTPServers(hostSpec)
	if err != nil {
		return err
	}

	ftpPort := b.FTPSPort
	if ftpPort == 0 {
		ftpPort = defaultPort
	}

	fmt.Printf("FTP bounce scan\n")
	fmt.Printf("  Relay creds:  %s:***@%s\n", user, hostSpec)
	fmt.Printf("  Target:       %s\n", targetDisplay)
	if len(b.Ports) > 0 {
		fmt.Printf("  Ports:        %s\n", formatPortList(b.Ports))
	} else {
		fmt.Printf("  Ports:        (capability check only)\n")
	}
	fmt.Printf("  FTP servers:  %d host(s)\n\n", len(hosts))

	for _, host := range hosts {
		addr := net.JoinHostPort(host, strconv.Itoa(ftpPort))
		b.scanHost(addr, host, user, pass, target)
	}
	return nil
}

func (b *BounceScanner) scanHost(addr, displayHost, user, pass string, target net.IP) {
	fc, err := dialFTP(addr)
	if err != nil {
		fmt.Printf("[%s] connect failed: %v\n", displayHost, err)
		return
	}
	defer fc.quit()

	ok, err := fc.login(user, pass)
	if err != nil {
		fmt.Printf("[%s] login error: %v\n", displayHost, err)
		return
	}
	if !ok {
		fmt.Printf("[%s] authentication rejected\n", displayHost)
		return
	}

	cap := checkBounceCapability(fc, target)
	switch cap {
	case bounceWorking:
		fmt.Printf("\x1b[32m[%s] bounce working!\x1b[0m\n", displayHost)
	case bounceLowPortsBlocked:
		fmt.Printf("\x1b[33m[%s] bounce works for ports >= 1025 (low ports forbidden)\x1b[0m\n", displayHost)
	case bounceDenied:
		fmt.Printf("[%s] server forbids bouncing (PORT rejected)\n", displayHost)
		return
	default:
		fmt.Printf("[%s] bounce capability unknown\n", displayHost)
	}

	if len(b.Ports) == 0 {
		fmt.Println()
		return
	}

	fmt.Printf("[%s] scanning %s via bounce:\n", displayHost, target)
	for _, port := range b.Ports {
		state, detail := probeBouncedPort(fc, target, port)
		line := fmt.Sprintf("  %d/tcp  %s", port, state)
		if detail != "" {
			line += "  (" + detail + ")"
		}
		switch state {
		case PortOpen:
			fmt.Printf("\x1b[32m%s\x1b[0m\n", line)
		case PortClosed:
			fmt.Printf("%s\n", line)
		default:
			fmt.Printf("\x1b[33m%s\x1b[0m\n", line)
		}
	}
	fmt.Println()
}

type bounceCap int

const (
	bounceUnknown bounceCap = iota
	bounceDenied
	bounceLowPortsBlocked
	bounceWorking
)

// checkBounceCapability: high PORT (80,80) then low (0,80).
func checkBounceCapability(fc *ftpConn, target net.IP) bounceCap {
	ip := target.To4()
	highOK := portAccepted(fc, ip, 80, 80)
	if !highOK {
		return bounceDenied
	}
	lowOK := portAccepted(fc, ip, 0, 80)
	if !lowOK {
		return bounceLowPortsBlocked
	}
	return bounceWorking
}

// resolveBounceTarget resolves the bounce probe/scan target to an IPv4 address.
func resolveBounceTarget(targetStr string) (net.IP, string, error) {
	targetStr = strings.TrimSpace(targetStr)
	if targetStr == "" {
		return nil, "", fmt.Errorf("target IP is required (user:password@host <target-ip>)")
	}
	if ip := net.ParseIP(targetStr); ip != nil && ip.To4() != nil {
		return ip.To4(), targetStr, nil
	}
	addrs, err := net.LookupHost(targetStr)
	if err != nil {
		return nil, "", fmt.Errorf("resolve target %q: %w", targetStr, err)
	}
	if len(addrs) == 0 {
		return nil, "", fmt.Errorf("resolve target %q: no addresses", targetStr)
	}
	ip := net.ParseIP(addrs[0])
	if ip == nil || ip.To4() == nil {
		return nil, "", fmt.Errorf("target %q resolved to non-IPv4 address", targetStr)
	}
	display := targetStr
	if targetStr != addrs[0] {
		display = fmt.Sprintf("%s (%s)", targetStr, addrs[0])
	}
	return ip.To4(), display, nil
}

func portAccepted(fc *ftpConn, ip net.IP, pHi, pLo int) bool {
	code, _, err := fc.cmd(portCommand(ip, pHi, pLo))
	if err != nil {
		return false
	}
	return code >= 200 && code <= 299
}

func portCommand(ip net.IP, pHi, pLo int) string {
	v4 := ip.To4()
	return fmt.Sprintf("PORT %d,%d,%d,%d,%d,%d", v4[0], v4[1], v4[2], v4[3], pHi, pLo)
}

func probeBouncedPort(fc *ftpConn, target net.IP, port int) (PortState, string) {
	pHi := port / 256
	pLo := port % 256
	code, msg, err := fc.cmd(portCommand(target, pHi, pLo))
	if err != nil {
		return PortUnknown, err.Error()
	}
	if code < 200 || code > 299 {
		return PortBounceDenied, strings.TrimSpace(msg)
	}

	// Trigger the bounced data connection (classic FTP port scan).
	code, msg, err = fc.cmd("LIST")
	if err != nil {
		return PortUnknown, err.Error()
	}
	msg = strings.TrimSpace(msg)

	switch {
	case code == 150 || code == 125:
		finalCode, finalMsg, err := fc.readResp()
		if err != nil {
			return PortOpen, msg
		}
		finalMsg = strings.TrimSpace(finalMsg)
		switch finalCode {
		case 226:
			return PortOpen, finalMsg
		case 425, 426:
			return PortClosed, finalMsg
		default:
			return PortOpen, fmt.Sprintf("%d %s", finalCode, finalMsg)
		}
	case code == 425:
		return PortClosed, msg
	case code == 426:
		return PortClosed, msg
	case code == 530:
		return PortFiltered, msg
	case code >= 500:
		return PortFiltered, msg
	default:
		return PortUnknown, fmt.Sprintf("%d %s", code, msg)
	}
}

func parseBounceSpec(s string) (user, pass, host, target string, err error) {
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, " ", 2)
	if len(parts) < 2 || strings.TrimSpace(parts[1]) == "" {
		return "", "", "", "", fmt.Errorf("expected user:password@host <target-ip>")
	}
	target = strings.TrimSpace(parts[1])
	user, pass, host, err = parseBounceCredServer(parts[0])
	return user, pass, host, target, err
}

func parseBounceCredServer(s string) (user, pass, host string, err error) {
	s = strings.TrimSpace(s)
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return "", "", "", fmt.Errorf("expected user:password@host (e.g. anonymous:IEUser@@192.168.1.1)")
	}
	host = strings.TrimSpace(s[at+1:])
	if host == "" {
		return "", "", "", fmt.Errorf("missing FTP server host after @")
	}
	cred := s[:at]
	colon := strings.Index(cred, ":")
	if colon < 0 {
		return "", "", "", fmt.Errorf("expected user:password@host")
	}
	user = cred[:colon]
	pass = cred[colon+1:]
	if user == "" {
		return "", "", "", fmt.Errorf("username cannot be empty")
	}
	return user, pass, host, nil
}

func expandFTPServers(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty FTP server spec")
	}

	if strings.Contains(spec, "/") {
		return cidrHostStrings(spec)
	}
	if dash := strings.LastIndex(spec, "-"); dash > 0 {
		if hosts, err := lastOctetRange(spec); err == nil {
			return hosts, nil
		}
	}

	if net.ParseIP(spec) != nil {
		return []string{spec}, nil
	}
	// hostname — single entry (dialFTP resolves via net.Dial)
	return []string{spec}, nil
}

func cidrHostStrings(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	v4 := ipNet.IP.To4()
	if v4 == nil {
		return nil, fmt.Errorf("only IPv4 CIDR ranges are supported")
	}
	ones, bits := ipNet.Mask.Size()
	if ones > 30 {
		return nil, fmt.Errorf("CIDR /%d is too small (use /30 or wider)", ones)
	}
	network := binary.BigEndian.Uint32(v4)
	total := uint32(1) << uint(bits-ones)
	out := make([]string, 0, int(total)-2)
	for i := uint32(1); i < total-1; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, network+i)
		out = append(out, ip.String())
	}
	return out, nil
}

func lastOctetRange(s string) ([]string, error) {
	dash := strings.LastIndex(s, "-")
	start := net.ParseIP(s[:dash])
	if start == nil || start.To4() == nil {
		return nil, fmt.Errorf("expected format like 192.168.1.2-254")
	}
	endOctet, err := strconv.Atoi(s[dash+1:])
	if err != nil || endOctet < 0 || endOctet > 255 {
		return nil, fmt.Errorf("expected format like 192.168.1.2-254")
	}
	start = start.To4()
	if int(start[3]) > endOctet {
		return nil, fmt.Errorf("invalid range %q: start octet > end octet", s)
	}
	var out []string
	for o := int(start[3]); o <= endOctet; o++ {
		ip := append(net.IP{}, start...)
		ip[3] = byte(o)
		out = append(out, ip.String())
	}
	return out, nil
}

func formatPortList(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

// ParsePortList parses a comma-separated port list (e.g. "22,80,443").
func ParsePortList(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty port list")
	}
	var ports []int
	seen := make(map[int]bool)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports in %q", s)
	}
	return ports, nil
}

// ParseSinglePort returns the first port from a spec (single int or comma list).
func ParseSinglePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if strings.Contains(s, ",") {
		ports, err := ParsePortList(s)
		if err != nil {
			return 0, err
		}
		return ports[0], nil
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 0 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return p, nil
}
