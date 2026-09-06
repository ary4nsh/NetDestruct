package snmp

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

const (
	v3ProbeTimeout    = 300 * time.Millisecond
	v3DiscoverTimeout = 3000 * time.Millisecond
)

type v3EngineInfo struct {
	id    []byte
	boots uint32
	time  uint32
}

type v3Client struct {
	conn      *net.UDPConn
	host      string
	port      int
	timeout   time.Duration
	engine    v3EngineInfo
	msgID     uint32
	reqID     uint32
	saltSeq   uint64
	keyCache  map[string][]byte
	lastTrace string
}

func newV3Client(host string, port int, timeout time.Duration) (*v3Client, error) {
	if timeout <= 0 {
		timeout = v3ProbeTimeout
	}
	if port <= 0 {
		port = defaultPort
	}
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return nil, err
	}
	return &v3Client{
		conn:     conn,
		host:     host,
		port:     port,
		timeout:  timeout,
		keyCache: make(map[string][]byte),
	}, nil
}

func (c *v3Client) discoveryFailed() bool {
	if c.lastTrace == "" {
		return false
	}
	return strings.Contains(c.lastTrace, "no engine after discover") ||
		strings.Contains(c.lastTrace, "discover xchg:") ||
		strings.Contains(c.lastTrace, "discover parse:") ||
		strings.Contains(c.lastTrace, "discover build:")
}

func (c *v3Client) trace(format string, args ...interface{}) {
	c.lastTrace = fmt.Sprintf(format, args...)
}

// resetSession redials UDP (new source port per use).
func (c *v3Client) resetSession() error {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.engine = v3EngineInfo{}
	c.msgID = 0
	c.reqID = 0
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", c.host, c.port))
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return err
	}
	c.conn = conn
	return nil
}

func (c *v3Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *v3Client) hasEngine() bool {
	return len(c.engine.id) > 0
}

// discoverEngine runs an RFC 3414 engineID probe (first packet per snmpwalk).
func (c *v3Client) discoverEngine() {
	usm := &v3USM{}
	flags := byte(v3FlagNoAuthNoPriv)
	getPDU := buildEmptyGetPDU(int(c.nextReqID()))
	packet, err := buildV3GetPacket(int(c.nextMsgID()), 0, flags, usm, getPDU)
	if err != nil {
		c.trace("discover build: %v", err)
		return
	}
	resp, err := c.exchange(packet)
	if err != nil {
		c.trace("discover xchg: %v", err)
		return
	}
	parsed, err := parseV3Packet(resp, nil)
	if err != nil {
		c.trace("discover parse: %v", err)
		return
	}
	c.syncEngine(parsed)
	c.trace("discover ok engine=%x boots=%d time=%d report=%s outcome=%d",
		c.engine.id, c.engine.boots, c.engine.time, parsed.reportOID, parsed.outcome)
}

// tryDiscoverEngine sends an RFC 3414 probe (optional, non-fatal).
func (c *v3Client) tryDiscoverEngine() {
	if c.hasEngine() {
		return
	}
	c.discoverEngine()
}

// learnEngineFromUsers tries to learn engine ID from valid usernames before auth tests.
func (c *v3Client) learnEngineFromUsers(users []string) {
	if c.hasEngine() {
		return
	}
	for _, user := range users {
		for attempt := 0; attempt < 2; attempt++ {
			hadEngine := c.hasEngine()
			_, _, _ = c.sendProbe(user, v3Attempt{Level: "noAuthNoPriv"})
			if c.hasEngine() {
				return
			}
			if hadEngine {
				break
			}
		}
	}
}

// enumUser checks whether a username exists (new session, discover, probe sysDescr).
func (c *v3Client) enumUser(user string) (v3ProbeOutcome, string) {
	c.lastTrace = ""
	if err := c.resetSession(); err != nil {
		c.trace("reset: %v", err)
		return v3OutcomeFail, ""
	}
	c.discoverEngine()
	if !c.hasEngine() {
		c.trace("no engine after discover")
		return v3OutcomeFail, ""
	}
	for attempt := 0; attempt < 2; attempt++ {
		outcome, desc, err := c.sendProbe(user, v3Attempt{Level: "noAuthNoPriv"})
		if err != nil {
			c.trace("probe attempt=%d xchg: %v", attempt, err)
			if attempt == 0 {
				continue
			}
			return v3OutcomeFail, ""
		}
		c.trace("probe attempt=%d outcome=%d desc=%q", attempt, outcome, desc)
		switch outcome {
		case v3OutcomeUnknownUser:
			return outcome, desc
		case v3OutcomeOK, v3OutcomeUserExists:
			return outcome, desc
		case v3OutcomeFail:
			if attempt == 0 {
				continue
			}
			return v3OutcomeFail, ""
		}
	}
	return v3OutcomeFail, ""
}

func (c *v3Client) probe(user string, att v3Attempt) (v3ProbeOutcome, string) {
	if att.Level != "noAuthNoPriv" && !c.hasEngine() {
		return v3OutcomeFail, ""
	}
	for attempt := 0; attempt < 2; attempt++ {
		hadEngine := c.hasEngine()
		outcome, desc, err := c.sendProbe(user, att)
		if err != nil {
			return v3OutcomeFail, ""
		}
		switch outcome {
		case v3OutcomeOK:
			return outcome, desc
		case v3OutcomeUserExists:
			if !hadEngine && c.hasEngine() && att.Level != "noAuthNoPriv" {
				continue
			}
			return outcome, desc
		default:
			return outcome, desc
		}
	}
	return v3OutcomeFail, ""
}

func (c *v3Client) sendProbe(user string, att v3Attempt) (v3ProbeOutcome, string, error) {
	authProto := v3AuthByName(att.AuthName)
	privProto := v3PrivByName(att.PrivName)

	var flags byte
	switch att.Level {
	case "noAuthNoPriv":
		flags = v3FlagNoAuthNoPriv
	case "authNoPriv":
		flags = v3FlagAuthNoPriv
	case "authPriv":
		flags = v3FlagAuthPriv
	default:
		return v3OutcomeFail, "", nil
	}

	usm, err := c.buildUSM(user, authProto, privProto, att.AuthPass, att.PrivPass)
	if err != nil {
		return v3OutcomeFail, "", nil
	}

	reqID := int(c.nextReqID())
	getPDU := buildGetPDU(reqID, oidSysDescr)
	packet, err := buildV3GetPacket(int(c.nextMsgID()), reqID, flags, usm, getPDU)
	if err != nil {
		return v3OutcomeFail, "", nil
	}

	resp, err := c.exchange(packet)
	if err != nil {
		return v3OutcomeFail, "", err
	}

	parsed, err := parseV3Packet(resp, usm)
	if err != nil {
		c.trace("parse: %v", err)
		return v3OutcomeFail, "", nil
	}
	c.syncEngine(parsed)

	if c.hasEngine() && att.Level != "noAuthNoPriv" {
		c.engine.time++
	}

	switch parsed.outcome {
	case v3OutcomeOK:
		return v3OutcomeOK, parsed.sysDescr, nil
	case v3OutcomeUnknownUser:
		return v3OutcomeUnknownUser, "", nil
	case v3OutcomeUserExists:
		return v3OutcomeUserExists, "", nil
	default:
		return v3OutcomeFail, "", nil
	}
}

func (c *v3Client) syncEngine(parsed *v3Parsed) {
	if parsed == nil {
		return
	}
	if len(parsed.engineID) > 0 {
		c.engine.id = append([]byte(nil), parsed.engineID...)
		c.engine.boots = parsed.engineBoot
		c.engine.time = parsed.engineTime
		return
	}
	if parsed.engineTime != 0 {
		c.engine.time = parsed.engineTime
	}
	if parsed.engineBoot != 0 {
		c.engine.boots = parsed.engineBoot
	}
}

func (c *v3Client) buildUSM(user string, authProto v3AuthProto, privProto v3PrivProto, authPass, privPass string) (*v3USM, error) {
	usm := &v3USM{
		user:      user,
		authProto: authProto,
		privProto: privProto,
		authPass:  authPass,
		privPass:  privPass,
	}
	if c.hasEngine() {
		usm.engineID = append([]byte(nil), c.engine.id...)
		usm.engineBoot = c.engine.boots
		usm.engineTime = c.engine.time
	}
	seq := atomic.AddUint64(&c.saltSeq, 1)
	usm.aesSalt = seq
	usm.desSalt = uint32(seq)

	if authProto > v3AuthNone && authPass != "" {
		if !c.hasEngine() {
			return nil, fmt.Errorf("engine id required for auth")
		}
		key, err := c.localizedKey(authProto, privProto, authPass, false)
		if err != nil {
			return nil, err
		}
		usm.secretKey = key
	}
	if privProto > v3PrivNone && privPass != "" {
		if !c.hasEngine() {
			return nil, fmt.Errorf("engine id required for priv")
		}
		key, err := c.localizedKey(authProto, privProto, privPass, true)
		if err != nil {
			return nil, err
		}
		usm.privKey = key
	}
	return usm, nil
}

func (c *v3Client) localizedKey(authProto v3AuthProto, privProto v3PrivProto, password string, priv bool) ([]byte, error) {
	cacheKey := fmt.Sprintf("%x:%d:%d:%s:%v", c.engine.id, authProto, privProto, password, priv)
	if key, ok := c.keyCache[cacheKey]; ok {
		return key, nil
	}
	var key []byte
	var err error
	if priv && (privProto == v3PrivAES || privProto == v3PrivAES192 || privProto == v3PrivAES256) {
		key, err = v3PrivKey(authProto, privProto, password, string(c.engine.id))
	} else {
		key, err = v3LocalizedKey(authProto, password, string(c.engine.id))
	}
	if err != nil {
		return nil, err
	}
	c.keyCache[cacheKey] = key
	return key, nil
}

func (c *v3Client) exchange(packet []byte) ([]byte, error) {
	timeout := c.timeout
	if !c.hasEngine() {
		timeout = v3DiscoverTimeout
	}
	if err := c.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(packet); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (c *v3Client) nextMsgID() uint32 {
	return atomic.AddUint32(&c.msgID, 1)
}

func (c *v3Client) nextReqID() uint32 {
	return atomic.AddUint32(&c.reqID, 1)
}

// setVarbinds sends an SNMPv3 SET with the given security flags and multiple varbinds.
func (c *v3Client) setVarbinds(user string, flags byte, authProto v3AuthProto, privProto v3PrivProto, authPass, privPass string, binds []v3VarBind) error {
	if !c.hasEngine() {
		c.discoverEngine()
	}
	if !c.hasEngine() {
		return fmt.Errorf("SNMP engine discovery failed")
	}
	usm, err := c.buildUSM(user, authProto, privProto, authPass, privPass)
	if err != nil {
		return err
	}
	reqID := int(c.nextReqID())
	setPDU := buildSetPDU(reqID, binds)
	packet, err := buildV3Packet(int(c.nextMsgID()), flags, usm, setPDU)
	if err != nil {
		return err
	}
	resp, err := c.exchange(packet)
	if err != nil {
		return err
	}
	parsed, err := parseV3Packet(resp, usm)
	if err != nil {
		return err
	}
	c.syncEngine(parsed)
	if flags&v3FlagAuthNoPriv != 0 {
		c.engine.time++
	}
	if parsed.outcome == v3OutcomeOK {
		return nil
	}
	if parsed.errStatus != 0 {
		return fmt.Errorf("snmp error status %d (%s)", parsed.errStatus, snmpErrorName(parsed.errStatus))
	}
	if parsed.reportOID != "" {
		return fmt.Errorf("snmp report: %s", parsed.reportOID)
	}
	return fmt.Errorf("snmp SET failed")
}

func buildEmptyGetPDU(reqID int) []byte {
	varBindList := asn1Seq(nil)
	pduBody := append(append(append(asn1Int(reqID), asn1Int(0)...), asn1Int(0)...), varBindList...)
	return asn1TLV(v3PDUSDiscoveryGet, pduBody)
}
