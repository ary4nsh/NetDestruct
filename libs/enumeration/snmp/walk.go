package snmp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const maxWalkSteps = 8192

// Walker performs SNMPv2c GET-NEXT walks against one host.
type Walker struct {
	Target    string
	Port      int
	Community string
	OIDs      string // comma-separated; empty = default mib-2
	Timeout   time.Duration
	Out       io.Writer
}

type VarBind struct {
	OID  []int
	Tag  byte
	Data []byte
}

// Run walks each requested OID subtree and prints varbind lines.
func (w *Walker) Run() error {
	host := strings.TrimSpace(w.Target)
	community := strings.TrimSpace(w.Community)
	if host == "" {
		return fmt.Errorf("--snmp --walk requires --target <ip>")
	}
	if community == "" {
		return fmt.Errorf("--snmp --walk requires --community <string>")
	}

	port := w.Port
	if port <= 0 {
		port = defaultPort
	}
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	out := w.Out
	if out == nil {
		out = os.Stdout
	}

	roots, err := parseOIDList(w.OIDs)
	if err != nil {
		return fmt.Errorf("invalid --oid: %w", err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.LookupIP(host)
		if err != nil || len(addrs) == 0 {
			return fmt.Errorf("resolve %q: %w", host, err)
		}
		ip = addrs[0]
	}

	addr := &net.UDPAddr{IP: ip, Port: port}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	fmt.Fprintf(out, "%s Target: %s:%d  Community: %s  Version: SNMPv2c\n", snmpTag, ip, port, community)
	fmt.Fprintf(out, "%s Walking %d subtree(s)\n", snmpTag, len(roots))

	total := 0
	for _, root := range roots {
		end := oidEndBound(root)
		fmt.Fprintf(out, "%s Subtree %s\n", snmpTag, formatSymbolicOID(root))
		current := append([]int(nil), root...)
		for step := 0; step < maxWalkSteps; step++ {
			vb, err := w.getNext(conn, community, current, timeout)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					fmt.Fprintf(out, "%s Walk timeout at %s\n", snmpTag, formatSymbolicOID(current))
					break
				}
				return err
			}
			if vb == nil {
				break
			}
			if oidCompare(vb.OID, end) >= 0 {
				break
			}
			if isSNMPException(vb.Tag) {
				break
			}
			fmt.Fprintf(out, "%s %s = %s\n", snmpTag, formatSymbolicOID(vb.OID), formatSNMPValue(vb.Tag, vb.Data))
			total++
			current = vb.OID
		}
	}
	fmt.Fprintf(out, "%s Done (%d variables)\n", snmpTag, total)
	return nil
}

func (w *Walker) getNext(conn *net.UDPConn, community string, oid []int, timeout time.Duration) (*VarBind, error) {
	reqID := int(time.Now().UnixNano() & 0x7fffffff)
	req := buildGetNextRequest(community, reqID, oid)
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseGetNextResponse(buf[:n], reqID)
}

func buildGetNextRequest(community string, reqID int, oid []int) []byte {
	nullValue := []byte{0x05, 0x00}
	varBind := asn1Seq(append(encodeOID(oid), nullValue...))
	varBindList := asn1Seq(varBind)
	pduBody := append(append(append(asn1Int(reqID), asn1Int(0)...), asn1Int(0)...), varBindList...)
	getNextPDU := asn1TLV(0xa1, pduBody) // GetNextRequest-PDU
	msg := append(append(append(asn1Int(1), asn1OctetString([]byte(community))...), getNextPDU...), []byte{}...)
	return asn1Seq(msg)
}

func parseGetNextResponse(b []byte, reqID int) (*VarBind, error) {
	i := 0
	if readByte(b, &i) != 0x30 {
		return nil, fmt.Errorf("invalid snmp packet")
	}
	if _, ok := readLength(b, &i); !ok {
		return nil, fmt.Errorf("invalid snmp length")
	}
	if readByte(b, &i) != 0x02 {
		return nil, fmt.Errorf("missing snmp version")
	}
	ver, ok := readInt(b, &i)
	if !ok {
		return nil, fmt.Errorf("invalid snmp version")
	}
	if ver != 1 {
		return nil, fmt.Errorf("unexpected snmp version %d (expected 1 for SNMPv2c)", ver)
	}
	if readByte(b, &i) != 0x04 {
		return nil, fmt.Errorf("missing community")
	}
	if _, ok := readOctets(b, &i); !ok {
		return nil, fmt.Errorf("invalid community")
	}
	if readByte(b, &i) != 0xa2 {
		return nil, fmt.Errorf("expected response PDU")
	}
	if _, ok := readLength(b, &i); !ok {
		return nil, fmt.Errorf("invalid pdu length")
	}
	if readByte(b, &i) != 0x02 {
		return nil, fmt.Errorf("missing request id")
	}
	gotReqID, ok := readInt(b, &i)
	if !ok {
		return nil, fmt.Errorf("invalid request id")
	}
	if gotReqID != reqID {
		return nil, fmt.Errorf("request id mismatch")
	}
	if readByte(b, &i) != 0x02 {
		return nil, fmt.Errorf("missing error status")
	}
	errStatus, ok := readInt(b, &i)
	if !ok {
		return nil, fmt.Errorf("invalid error status")
	}
	if readByte(b, &i) != 0x02 {
		return nil, fmt.Errorf("missing error index")
	}
	if _, ok := readInt(b, &i); !ok {
		return nil, fmt.Errorf("invalid error index")
	}
	if errStatus != 0 {
		return nil, fmt.Errorf("snmp error status %d", errStatus)
	}
	if readByte(b, &i) != 0x30 {
		return nil, nil
	}
	if _, ok := readLength(b, &i); !ok {
		return nil, nil
	}
	if readByte(b, &i) != 0x30 {
		return nil, nil
	}
	if _, ok := readLength(b, &i); !ok {
		return nil, nil
	}
	if readByte(b, &i) != 0x06 {
		return nil, nil
	}
	oidRaw, ok := readOctets(b, &i)
	if !ok {
		return nil, fmt.Errorf("invalid oid in response")
	}
	oid, err := decodeOID(oidRaw)
	if err != nil {
		return nil, err
	}
	tag := readByte(b, &i)
	val, ok := readOctets(b, &i)
	if !ok {
		return nil, fmt.Errorf("invalid value in response")
	}
	return &VarBind{OID: oid, Tag: tag, Data: val}, nil
}
