package smbvers

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	smb2CmdTreeConnect = 0x0003
	smb2CmdCreate      = 0x0005
	smb2CmdClose       = 0x0006
	smb2CmdRead        = 0x0008
	smb2CmdWrite       = 0x0009
	smb2CmdIoctl          = 0x000B
	smb2CmdQueryDirectory = 0x000E

	fsctlPipeTransceive = 0x0011c017

	fileListDirectory   = 0x00000001
	fileTraverse        = 0x00000020
	fileDirectoryFile   = 0x00000001
	synchronizeAccess   = 0x00100000
	fileShareReadWrite  = 0x00000003
	fileDirectoryInfo   = 0x01

	stWrongPassword        = 0xC000006A
	stInvalidInfoClass     = 0xC0000003
	stNotADirectory        = 0xC0000103
	stNoSuchFile           = 0xC000000F
	stInvalidParameter     = 0xC000000D
	stNetworkAccessDenied  = 0xC00000CA
	stConnectionRefused    = 0xC0000236

	fileOpen             = 0x00000001
	fileNonDirectoryFile = 0x00000040
	pipeDesiredAccess = 0x00000003 // FILE_READ_DATA | FILE_WRITE_DATA
	pipeShareAccess   = 0x00000001 // FILE_SHARE_READ

	stAccessDenied     = 0xC0000022
	stPipeBusy         = 0xC00000AE
	stPending          = 0x00000103
)

type fileID [16]byte

// SMBSession is a persistent SMB2 session used for RPC enumeration.
type SMBSession struct {
	conn      net.Conn
	host      string
	port      int
	sessionID uint64
	treeID    uint32
	msgID     uint64
	domain      string
	user        string
	pass        string
	guest       bool
	dialect     uint16
	signingKey  []byte
	signActive  bool
	signingRequired bool
	preauthHash []byte
	maxReadSize   uint32
	maxWriteSize  uint32
	samr        *boundPipe
	srvs        *boundPipe
}

func smb2PutSessionID(hdr []byte, sessionID uint64) {
	putU64(hdr[40:48], sessionID)
}

func smb2PutTreeID(hdr []byte, treeID uint32) {
	binary.LittleEndian.PutUint32(hdr[36:40], treeID)
}

// OpenSMBSession negotiates SMB2 and completes NTLM session setup.
func OpenSMBSession(host string, port int, user, pass, domain string) (*SMBSession, LoginOutcome, error) {
	if port <= 0 {
		port = portDirect
	}
	builds := []func() []byte{
		buildSMB2NegotiateLegacy,
		buildSMB2NegotiatePreferred,
		buildSMB2Negotiate311,
		buildSMB2Negotiate202,
	}
	blobs := []func() []byte{
		func() []byte { return wrapSPNEGONTLMNegotiate(buildNTLMNegotiate()) },
		buildNTLMNegotiate,
	}
	var lastErr error
	for _, build := range builds {
		for _, blobFn := range blobs {
			s, outcome, err := tryOpenSession(host, port, user, pass, domain, build, blobFn)
			if err == nil {
				return s, outcome, nil
			}
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("session setup failed")
	}
	return nil, LoginFail, lastErr
}

func tryOpenSession(host string, port int, user, pass, domain string, build func() []byte, blobFn func() []byte) (*SMBSession, LoginOutcome, error) {
	conn, sid, nego, preauth, err := smb2ConnectAndNegotiate(host, port, build)
	if err != nil {
		return nil, LoginFail, err
	}
	s := &SMBSession{conn: conn, host: host, port: port, sessionID: sid, msgID: 1, dialect: nego.Dialect, preauthHash: preauth, maxReadSize: nego.MaxReadSize, maxWriteSize: nego.MaxWriteSize}

	ch, sid2, err := smb2RequestNTLMChallenge(conn, sid, s.nextMsg(), blobFn(), &preauth)
	if err != nil {
		conn.Close()
		return nil, LoginFail, err
	}
	s.sessionID = sid2
	s.preauthHash = preauth
	s.domain = loginDomainForNTLM(ch, domain)

	auth, sessionKey := buildNTLMv2Authenticate(ch, user, pass, s.domain)
	s.signingRequired = nego.SigningRequired || nego.Dialect >= 0x0311
	hasSessionKey := len(sessionKey) > 0
	s.signActive = s.signingRequired || hasSessionKey
	hdr := smb2RequestHeader(smb2CmdSessionSetup, s.nextMsg())
	smb2PutSessionID(hdr, s.sessionID)
	authReq := append(hdr, buildSMB2SessionSetupRequest(auth)...)
	updatePreauthHash(&s.preauthHash, authReq)
	if s.signActive && hasSessionKey {
		s.signingKey = deriveSigningKey(sessionKey, s.dialect, s.preauthHash, s.dialect >= 0x0300 || s.signingRequired)
	}
	if err := netbiosWrite(conn, authReq); err != nil {
		conn.Close()
		return nil, LoginFail, err
	}
	resp, err := netbiosRead(conn)
	if err != nil {
		conn.Close()
		return nil, LoginFail, err
	}
	updatePreauthHash(&s.preauthHash, smbPayload(resp))
	if sid := smb2SessionID(resp); sid != 0 {
		s.sessionID = sid
	}
	if s.signActive && hasSessionKey && s.dialect >= 0x0311 {
		s.signingKey = deriveSigningKey(sessionKey, s.dialect, s.preauthHash, true)
	}
	st := smb2Status(resp)
	outcome := mapLoginStatus(st)
	if st == stSuccess && smb2SessionFlags(resp)&0x0001 != 0 {
		outcome = LoginGuest
		s.guest = true
	}
	if st != stSuccess {
		conn.Close()
		return nil, outcome, fmt.Errorf("session setup status 0x%08x", st)
	}
	s.user = user
	s.pass = pass
	return s, outcome, nil
}

func (s *SMBSession) Credentials() (user, pass, domain string) {
	return s.user, s.pass, s.domain
}

func (s *SMBSession) HostPort() (string, int) {
	return s.host, s.port
}

func (s *SMBSession) Close() {
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

func (s *SMBSession) nextMsg() uint64 {
	id := s.msgID
	s.msgID++
	return id
}

func (s *SMBSession) refreshDeadline() {
	_ = s.conn.SetDeadline(time.Now().Add(connTimeout))
}

func (s *SMBSession) writeSMB(pkt []byte) error {
	if s.signActive {
		signSMB2Packet(pkt, s.signingKey, s.dialect)
	}
	return netbiosWrite(s.conn, pkt)
}

func (s *SMBSession) TreeConnectIPC() error {
	path := utf16LE(fmt.Sprintf(`\\%s\IPC$`, s.host))
	body := make([]byte, 0, 8+len(path))
	body = append(body, u16(9)...)
	body = append(body, 0x00, 0x00)
	off := uint16(64 + 8)
	body = append(body, u16(off)...)
	body = append(body, u16(uint16(len(path)))...)
	body = append(body, path...)

	s.refreshDeadline()
	hdr := smb2RequestHeader(smb2CmdTreeConnect, s.nextMsg())
	smb2PutSessionID(hdr, s.sessionID)
	if err := s.writeSMB(append(hdr, body...)); err != nil {
		return err
	}
	resp, err := netbiosRead(s.conn)
	if err != nil {
		return err
	}
	st := smb2Status(resp)
	if st != stSuccess {
		return fmt.Errorf("tree connect IPC$ status 0x%08x", st)
	}
	off2 := smb2Offset(resp)
	if off2 < 0 || len(resp) < off2+64+8 {
		return fmt.Errorf("short tree connect response")
	}
	s.treeID = binary.LittleEndian.Uint32(resp[off2+36 : off2+40])
	return nil
}

func (s *SMBSession) openPipe(name string) (fileID, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(200 * time.Millisecond)
		}
		fid, err := s.openPipeOnce(name)
		if err == nil {
			return fid, nil
		}
		lastErr = err
		if st, ok := smbStatusFromErr(err); !ok || (st != 0xC00000C9 && st != 0xC00000AC && st != stPipeBusy) {
			return fileID{}, err
		}
	}
	return fileID{}, lastErr
}

func smbStatusFromErr(err error) (uint32, bool) {
	var st uint32
	if _, e := fmt.Sscanf(err.Error(), "%*s status 0x%x", &st); e == nil {
		return st, true
	}
	return 0, false
}

func (s *SMBSession) openPipeOnce(name string) (fileID, error) {
	nameU := utf16LE(name)
	const fixed = 56
	body := make([]byte, fixed+len(nameU))
	binary.LittleEndian.PutUint16(body[0:2], 57)
	body[2] = 0
	body[3] = 0
	binary.LittleEndian.PutUint32(body[4:8], 2) // SecurityImpersonation
	// body[8:16] SmbCreateFlags = 0
	// body[16:24] Reserved = 0
	binary.LittleEndian.PutUint32(body[24:28], 0x0012019F) // generic read/write for RPC pipes
	binary.LittleEndian.PutUint32(body[28:32], 0) // FileAttributes
	binary.LittleEndian.PutUint32(body[32:36], fileShareReadWrite)
	binary.LittleEndian.PutUint32(body[36:40], fileOpen)
	binary.LittleEndian.PutUint32(body[40:44], 0)
	nameOff := uint16(64 + fixed)
	binary.LittleEndian.PutUint16(body[44:46], nameOff)
	binary.LittleEndian.PutUint16(body[46:48], uint16(len(nameU)))
	copy(body[fixed:], nameU)

	s.refreshDeadline()
	hdr := smb2RequestHeader(smb2CmdCreate, s.nextMsg())
	smb2PutSessionID(hdr, s.sessionID)
	smb2PutTreeID(hdr, s.treeID)
	if err := s.writeSMB(append(hdr, body...)); err != nil {
		return fileID{}, err
	}
	resp, err := netbiosRead(s.conn)
	if err != nil {
		return fileID{}, err
	}
	st := smb2Status(resp)
	if st != stSuccess {
		return fileID{}, fmt.Errorf("open pipe %s status 0x%08x", name, st)
	}
	off := smb2Offset(resp)
	if off < 0 || len(resp) < off+128+16 {
		return fileID{}, fmt.Errorf("short create response")
	}
	var fid fileID
	copy(fid[:], resp[off+128:off+144])
	return fid, nil
}

func (s *SMBSession) closeFile(fid fileID) {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 24)
	copy(body[8:24], fid[:])
	s.refreshDeadline()
	hdr := smb2RequestHeader(smb2CmdClose, s.nextMsg())
	smb2PutSessionID(hdr, s.sessionID)
	smb2PutTreeID(hdr, s.treeID)
	_ = s.writeSMB(append(hdr, body...))
	_, _ = netbiosRead(s.conn)
}

func isPipeBusyErr(err error) bool {
	st, ok := smbStatusFromErr(err)
	return ok && (st == stPipeBusy || st == 0xC00000C9 || st == 0xC00000AC)
}

func (s *SMBSession) pipeTransact(fid fileID, in []byte) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		out, err := s.pipeIoctlTransceive(fid, in)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if st, ok := smbStatusFromErr(err); ok && st == 0x80000005 && len(out) > 0 {
			more, rerr := s.pipeRead(fid, 65535)
			if rerr == nil {
				return append(out, more...), nil
			}
			return out, nil
		}
		if !isPipeBusyErr(err) {
			break
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("pipe transact failed")
	}
	return nil, lastErr
}

func (s *SMBSession) pipeIoctlTransceive(fid fileID, in []byte) ([]byte, error) {
	const hdrSize = 64
	const bodyFixed = 56
	inOff := uint32(hdrSize + bodyFixed)
	outMax := uint32(4280)

	body := make([]byte, bodyFixed)
	binary.LittleEndian.PutUint16(body[0:2], 57)
	binary.LittleEndian.PutUint32(body[4:8], fsctlPipeTransceive)
	copy(body[8:24], fid[:])
	binary.LittleEndian.PutUint32(body[24:28], inOff)
	binary.LittleEndian.PutUint32(body[28:32], uint32(len(in)))
	binary.LittleEndian.PutUint32(body[32:36], 0)
	binary.LittleEndian.PutUint32(body[36:40], 0)
	binary.LittleEndian.PutUint32(body[40:44], 0)
	binary.LittleEndian.PutUint32(body[44:48], outMax)
	binary.LittleEndian.PutUint32(body[48:52], 1)

	payload := append(body, in...)

	reqHdr := smb2RequestHeader(smb2CmdIoctl, s.nextMsg())
	if s.dialect >= 0x0300 {
		smb2SetCreditCharge(reqHdr, 1)
	}
	smb2PutSessionID(reqHdr, s.sessionID)
	smb2PutTreeID(reqHdr, s.treeID)
	s.refreshDeadline()
	if err := s.writeSMB(append(reqHdr, payload...)); err != nil {
		return nil, err
	}
	resp, err := netbiosRead(s.conn)
	if err != nil {
		return nil, err
	}
	for smb2Status(resp) == stPending {
		resp, err = netbiosRead(s.conn)
		if err != nil {
			return nil, err
		}
	}
	out, err := parseIoctlPipeResponse(resp)
	if err != nil {
		st := smb2Status(resp)
		if st == 0x80000005 && len(out) > 0 {
			more, rerr := s.pipeRead(fid, 65535)
			if rerr != nil {
				return out, nil
			}
			return append(out, more...), nil
		}
		return out, err
	}
	return out, nil
}

func (s *SMBSession) pipeWriteRead(fid fileID, in []byte) ([]byte, error) {
	writeResp, err := s.pipeWrite(fid, in)
	if err != nil {
		return nil, fmt.Errorf("pipe write: %w", err)
	}
	if out := findRPCPayload(writeResp); len(out) > 0 {
		return out, nil
	}
	out, err := s.pipeRead(fid, 4280)
	if err != nil {
		return nil, fmt.Errorf("pipe read: %w", err)
	}
	return out, nil
}

func (s *SMBSession) pipeWrite(fid fileID, data []byte) ([]byte, error) {
	const bodyFixed = 48
	dataOff := uint16(64 + bodyFixed)
	body := make([]byte, bodyFixed+len(data))
	binary.LittleEndian.PutUint16(body[0:2], 49)
	binary.LittleEndian.PutUint16(body[2:4], dataOff)
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(data)))
	copy(body[16:32], fid[:])
	copy(body[bodyFixed:], data)

	hdr := smb2RequestHeader(smb2CmdWrite, s.nextMsg())
	smb2PutSessionID(hdr, s.sessionID)
	smb2PutTreeID(hdr, s.treeID)
	s.refreshDeadline()
	if err := s.writeSMB(append(hdr, body...)); err != nil {
		return nil, err
	}
	resp, err := netbiosRead(s.conn)
	if err != nil {
		return nil, err
	}
	st := smb2Status(resp)
	if st != stSuccess {
		return resp, fmt.Errorf("pipe write status 0x%08x", st)
	}
	return resp, nil
}

func (s *SMBSession) pipeRead(fid fileID, maxLen uint32) ([]byte, error) {
	readLen := maxLen
	if s.maxReadSize > 0 && readLen > s.maxReadSize {
		readLen = s.maxReadSize
	}
	if readLen == 0 {
		readLen = 4280
	}
	if s.dialect > 0x0202 && readLen > 65536 {
		readLen = 65536
	}
	body := make([]byte, 49)
	binary.LittleEndian.PutUint16(body[0:2], 49)
	body[2] = 0
	body[3] = 0
	binary.LittleEndian.PutUint32(body[4:8], readLen)
	copy(body[16:32], fid[:])

	hdr := smb2RequestHeader(smb2CmdRead, s.nextMsg())
	if s.dialect >= 0x0300 {
		charge := uint16(1 + (readLen-1)/65536)
		smb2SetCreditCharge(hdr, charge)
	}
	smb2PutSessionID(hdr, s.sessionID)
	smb2PutTreeID(hdr, s.treeID)
	s.refreshDeadline()
	if err := s.writeSMB(append(hdr, body...)); err != nil {
		return nil, err
	}
	resp, err := netbiosRead(s.conn)
	if err != nil {
		return nil, err
	}
	st := smb2Status(resp)
	if st != stSuccess && st != 0x80000005 {
		return nil, fmt.Errorf("pipe read status 0x%08x", st)
	}
	if out := findRPCPayload(resp); len(out) > 0 {
		return out, nil
	}
	off := smb2Offset(resp)
	if off < 0 || len(resp) < off+64+8 {
		return nil, fmt.Errorf("short read response")
	}
	rbody := resp[off+64:]
	dataOff := off + int(binary.LittleEndian.Uint16(rbody[2:4]))
	dataLen := binary.LittleEndian.Uint32(rbody[4:8])
	if dataLen == 0 || dataOff+int(dataLen) > len(resp) {
		return nil, fmt.Errorf("empty pipe read")
	}
	out := make([]byte, dataLen)
	copy(out, resp[dataOff:dataOff+int(dataLen)])
	return out, nil
}

func parseIoctlPipeResponse(resp []byte) ([]byte, error) {
	st := smb2Status(resp)
	extract := func() []byte {
		if out := findRPCPayload(resp); len(out) > 0 {
			return out
		}
		off := smb2Offset(resp)
		if off < 0 || len(resp) < off+64+48 {
			return nil
		}
		rbody := resp[off+64:]
		outCount := binary.LittleEndian.Uint32(rbody[36:40])
		if outCount == 0 {
			return nil
		}
		outStart := off + int(binary.LittleEndian.Uint32(rbody[32:36]))
		if outStart < 0 || outStart+int(outCount) > len(resp) {
			return nil
		}
		out := make([]byte, outCount)
		copy(out, resp[outStart:outStart+int(outCount)])
		if rpc := findRPCPayload(out); len(rpc) > 0 {
			return rpc
		}
		return out
	}
	out := extract()
	if st != stSuccess && st != 0x80000005 {
		return out, fmt.Errorf("pipe transact status 0x%08x", st)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pipe transact status 0x%08x (empty output)", st)
	}
	if st == 0x80000005 {
		return out, fmt.Errorf("pipe transact status 0x%08x", st)
	}
	return out, nil
}

func smb2SetCreditCharge(hdr []byte, charge uint16) {
	if charge == 0 {
		return
	}
	binary.LittleEndian.PutUint16(hdr[2:4], charge)
}

func findRPCPayload(pkt []byte) []byte {
	for i := 0; i+16 <= len(pkt); i++ {
		if pkt[i] != rpcVersion || pkt[i+1] != rpcVersionMinor {
			continue
		}
		ptype := pkt[i+2]
		if ptype != rpcBindAck && ptype != rpcResponse && ptype != 3 {
			continue
		}
		fragLen := int(binary.LittleEndian.Uint16(pkt[i+8 : i+10]))
		if fragLen < 16 || i+fragLen > len(pkt) {
			continue
		}
		out := make([]byte, fragLen)
		copy(out, pkt[i:i+fragLen])
		return out
	}
	return nil
}

func (s *SMBSession) rpcCall(pipeName string, bindUUID [16]byte, bindVer uint32, opnum uint16, stub []byte) ([]byte, error) {
	return s.rpcOnPipe(pipeName, bindUUID, bindVer, opnum, stub)
}

// PipeBind checks whether an RPC bind succeeds on a named pipe.
func (s *SMBSession) PipeBind(pipeName string, bindUUID [16]byte, bindVer uint32) bool {
	switch pipeName {
	case "samr":
		_, err := s.samrRPC()
		return err == nil
	case "srvsvc":
		_, err := s.srvsRPC()
		return err == nil
	default:
		bp, err := s.bindPipe(pipeName, bindUUID, bindVer)
		if err != nil {
			return false
		}
		s.closeFile(bp.fid)
		return true
	}
}
