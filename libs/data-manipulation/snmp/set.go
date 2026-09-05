package snmp

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	snmpenum "netdestruct/libs/enumeration/snmp"
)

const (
	defaultPort    = 161
	defaultTimeout = 1500 * time.Millisecond

	SNMPVersion1  = 0
	SNMPVersion2c = 1
)

// Setter sends an SNMP SET request (SNMPv1 or SNMPv2c), snmpset-style.
type Setter struct {
	Target    string
	Port      int
	Community string
	Version   int // SNMPVersion1 or SNMPVersion2c
	OID       string
	Value     string
	Timeout   time.Duration
	Out       io.Writer
}

// Run connects and issues an SNMP SET for one OID/value pair on each resolved target.
func (s *Setter) Run() error {
	targetSpec := strings.TrimSpace(s.Target)
	community := strings.TrimSpace(s.Community)
	oidSpec := strings.TrimSpace(s.OID)
	value := s.Value
	if targetSpec == "" {
		return fmt.Errorf("--snmp --set requires --target <ip|file>")
	}
	if community == "" {
		return fmt.Errorf("--snmp --set requires --community <string>")
	}
	if oidSpec == "" {
		return fmt.Errorf("--snmp --set requires --oid <oid>")
	}
	if value == "" {
		return fmt.Errorf("--snmp --set requires --value <data>")
	}
	if s.Version != SNMPVersion1 && s.Version != SNMPVersion2c {
		return fmt.Errorf("--snmp --set requires --v1 or --v2c")
	}

	port := s.Port
	if port <= 0 {
		port = defaultPort
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	out := s.Out
	if out == nil {
		out = os.Stdout
	}

	targets, err := snmpenum.ExpandTargets(targetSpec)
	if err != nil {
		return err
	}

	oid, err := snmpenum.ParseOIDSpec(oidSpec)
	if err != nil {
		return fmt.Errorf("invalid --oid: %w", err)
	}
	valueEnc, err := snmpenum.EncodeSetValue(value)
	if err != nil {
		return fmt.Errorf("invalid --value: %w", err)
	}

	verLabel := "SNMPv1"
	if s.Version == SNMPVersion2c {
		verLabel = "SNMPv2c"
	}

	if len(targets) > 1 {
		fmt.Fprintf(out, "%s Targets: %d  Community: %s  Version: %s\n",
			snmpenum.SNMPTag(), len(targets), community, verLabel)
	}

	var failed int
	for _, ip := range targets {
		if err := s.setOne(out, ip, port, community, verLabel, oid, value, valueEnc, timeout); err != nil {
			failed++
			fmt.Fprintf(out, "%s SET failed for %s: %v\n", snmpenum.SNMPTag(), ip, err)
		}
	}
	if failed > 0 {
		return fmt.Errorf("SET failed for %d of %d target(s)", failed, len(targets))
	}
	return nil
}

func (s *Setter) setOne(out io.Writer, ip net.IP, port int, community, verLabel string, oid []int, value string, valueEnc []byte, timeout time.Duration) error {
	fmt.Fprintf(out, "%s Target: %s:%d  Community: %s  Version: %s\n",
		snmpenum.SNMPTag(), ip, port, community, verLabel)
	fmt.Fprintf(out, "%s SET %s = %s\n", snmpenum.SNMPTag(), snmpenum.FormatSymbolicOID(oid), formatSetValueDisplay(value))

	addr := &net.UDPAddr{IP: ip, Port: port}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	reqID := int(time.Now().UnixNano() & 0x7fffffff)
	packet := snmpenum.BuildSetRequest(community, reqID, s.Version, oid, valueEnc)
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	vb, err := snmpenum.ParseSetResponse(buf[:n], reqID, s.Version)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "\x1b[32m[+]\x1b[0m SET successful\n")
	if vb != nil {
		fmt.Fprintf(out, "%s Response: %s = %s\n", snmpenum.SNMPTag(),
			snmpenum.FormatSymbolicOID(vb.OID), snmpenum.FormatSNMPValue(vb.Tag, vb.Data))
	}
	return nil
}

func formatSetValueDisplay(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
		return v
	}
	if _, err := strconv.ParseInt(v, 10, 64); err == nil {
		return v
	}
	return fmt.Sprintf("%q", v)
}
