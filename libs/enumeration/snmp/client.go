package snmp

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Session is an SNMPv2c UDP client for GET and GET-NEXT operations.
type Session struct {
	Conn      *net.UDPConn
	Community string
	Timeout   time.Duration
}

func dialSession(host string, port int, community string, timeout time.Duration) (*Session, net.IP, error) {
	host = strings.TrimSpace(host)
	community = strings.TrimSpace(community)
	if host == "" {
		return nil, nil, fmt.Errorf("target is required")
	}
	if community == "" {
		return nil, nil, fmt.Errorf("community is required")
	}
	if port <= 0 {
		port = defaultPort
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.LookupIP(host)
		if err != nil || len(addrs) == 0 {
			return nil, nil, fmt.Errorf("resolve %q: %w", host, err)
		}
		ip = addrs[0]
	}

	addr := &net.UDPAddr{IP: ip, Port: port}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return &Session{Conn: conn, Community: community, Timeout: timeout}, ip, nil
}

func (s *Session) Close() error {
	if s == nil || s.Conn == nil {
		return nil
	}
	return s.Conn.Close()
}

func (s *Session) Get(oid []int) (*VarBind, error) {
	reqID := int(time.Now().UnixNano() & 0x7fffffff)
	req := buildGetRequestV2c(s.Community, reqID, oid)
	if err := s.Conn.SetDeadline(time.Now().Add(s.Timeout)); err != nil {
		return nil, err
	}
	if _, err := s.Conn.Write(req); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, 65535)
	n, err := s.Conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseGetNextResponse(buf[:n], reqID)
}

func (s *Session) GetNext(oid []int) (*VarBind, error) {
	reqID := int(time.Now().UnixNano() & 0x7fffffff)
	req := buildGetNextRequest(s.Community, reqID, oid)
	if err := s.Conn.SetDeadline(time.Now().Add(s.Timeout)); err != nil {
		return nil, err
	}
	if _, err := s.Conn.Write(req); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, 65535)
	n, err := s.Conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseGetNextResponse(buf[:n], reqID)
}

func (s *Session) Walk(root []int) ([]VarBind, error) {
	end := oidEndBound(root)
	current := append([]int(nil), root...)
	var out []VarBind
	for step := 0; step < maxWalkSteps; step++ {
		vb, err := s.GetNext(current)
		if err != nil {
			return out, err
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
		out = append(out, *vb)
		current = vb.OID
	}
	return out, nil
}

func buildGetRequestV2c(community string, reqID int, oid []int) []byte {
	nullValue := []byte{0x05, 0x00}
	varBind := asn1Seq(append(encodeOID(oid), nullValue...))
	varBindList := asn1Seq(varBind)
	pduBody := append(append(append(asn1Int(reqID), asn1Int(0)...), asn1Int(0)...), varBindList...)
	getPDU := asn1TLV(0xa0, pduBody) // GetRequest-PDU
	msg := append(append(append(asn1Int(1), asn1OctetString([]byte(community))...), getPDU...), []byte{}...)
	return asn1Seq(msg)
}

func valueAsString(tag byte, raw []byte) string {
	if tag == 0x04 {
		return strings.TrimSpace(string(raw))
	}
	if tag == 0x05 || len(raw) == 0 {
		return ""
	}
	return strings.TrimSpace(formatSNMPValue(tag, raw))
}

func oidIndex(oid []int) int {
	if len(oid) == 0 {
		return 0
	}
	return oid[len(oid)-1]
}

func oidHasPrefix(oid, prefix []int) bool {
	if len(oid) < len(prefix) {
		return false
	}
	for i := range prefix {
		if oid[i] != prefix[i] {
			return false
		}
	}
	return true
}
