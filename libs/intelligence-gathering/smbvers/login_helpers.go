package smbvers

import (
	"fmt"
	"io"
	"net"
)

func netbiosPreamble(conn net.Conn, port int) error {
	if port != portNBSS {
		return nil
	}
	if _, err := conn.Write(netbiosSessionRequest()); err != nil {
		return err
	}
	ack := make([]byte, 4)
	if _, err := io.ReadFull(conn, ack); err != nil {
		return err
	}
	if ack[0] != 0x82 {
		return fmt.Errorf("netbios session rejected 0x%02x", ack[0])
	}
	return nil
}

func smb2ConnectAndNegotiate(host string, port int, build func() []byte) (net.Conn, uint64, *smb2NegotiateResult, []byte, error) {
	conn, err := dial(host, port)
	if err != nil {
		return nil, 0, nil, nil, err
	}
	if err := netbiosPreamble(conn, port); err != nil {
		conn.Close()
		return nil, 0, nil, nil, err
	}
	negoReq := build()
	preauth := preauthHashForNegotiateRequest(negoReq)
	updatePreauthHash(&preauth, negoReq)
	if err := netbiosWrite(conn, negoReq); err != nil {
		conn.Close()
		return nil, 0, nil, nil, err
	}
	negoResp, err := netbiosRead(conn)
	if err != nil {
		conn.Close()
		return nil, 0, nil, nil, err
	}
	res, err := parseSMB2NegotiateResponse(negoResp)
	if err != nil {
		conn.Close()
		return nil, 0, nil, nil, err
	}
	if res.Dialect >= 0x0311 {
		updatePreauthHash(&preauth, smbPayload(negoResp))
	} else {
		preauth = nil
	}
	return conn, smb2SessionID(negoResp), res, preauth, nil
}

func smb2RequestNTLMChallenge(conn net.Conn, sessionID, msgID uint64, secBlob []byte, preauth *[]byte) ([]byte, uint64, error) {
	hdr := smb2RequestHeader(smb2CmdSessionSetup, msgID)
	putU64(hdr[40:48], sessionID)
	req := append(hdr, buildSMB2SessionSetupRequest(secBlob)...)
	updatePreauthHash(preauth, req)
	if err := netbiosWrite(conn, req); err != nil {
		return nil, 0, err
	}
	resp, err := netbiosRead(conn)
	if err != nil {
		return nil, 0, err
	}
	updatePreauthHash(preauth, smbPayload(resp))
	return extractNTLMChallenge(resp)
}

func extractNTLMChallenge(pkt []byte) ([]byte, uint64, error) {
	st := smb2Status(pkt)
	if st != stSuccess && st != stMoreProcessing {
		return nil, 0, fmt.Errorf("session setup status 0x%08x", st)
	}
	sid := smb2SessionID(pkt)
	sec := smb2SecurityBuffer(pkt, 4)
	if ch := findNTLMMessage(sec, 2); ch != nil {
		return ch, sid, nil
	}
	if off := smb2Offset(pkt); off >= 0 {
		if ch := findNTLMMessage(pkt[off:], 2); ch != nil {
			return ch, sid, nil
		}
	}
	return nil, 0, fmt.Errorf("no NTLM challenge")
}

func smb2SessionFlags(pkt []byte) uint16 {
	off := smb2Offset(pkt)
	if off < 0 || len(pkt) < off+64+4 {
		return 0
	}
	return uint16(pkt[off+64+2]) | uint16(pkt[off+64+3])<<8
}

func putU64(b []byte, v uint64) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}

func preauthHashForNegotiateRequest(req []byte) []byte {
	if !negotiateRequestOffers311(req) {
		return nil
	}
	return newPreauthHash()
}

func negotiateRequestOffers311(req []byte) bool {
	off := smb2Offset(req)
	if off < 0 || len(req) < off+64+36 {
		return false
	}
	body := req[off+64:]
	count := int(binaryDialectCount(body))
	if count <= 0 {
		return false
	}
	base := 36
	if len(body) >= 64 {
		base = 64
	}
	end := base + count*2
	if end > len(body) {
		return false
	}
	for i := base; i+2 <= end; i += 2 {
		if uint16(body[i])|uint16(body[i+1])<<8 == 0x0311 {
			return true
		}
	}
	return false
}

func binaryDialectCount(body []byte) uint16 {
	if len(body) < 4 {
		return 0
	}
	return uint16(body[2]) | uint16(body[3])<<8
}

func smb2FetchChallenge(host string, port int) (conn net.Conn, challenge []byte, sessionID uint64, err error) {
	builds := []func() []byte{
		buildSMB2Negotiate202,
		buildSMB2NegotiateLegacy,
		buildSMB2Negotiate311,
	}
	blobs := []func() []byte{
		func() []byte { return wrapSPNEGONTLMNegotiate(buildNTLMNegotiate()) },
		buildNTLMNegotiate,
	}
	for _, build := range builds {
		for _, blobFn := range blobs {
			c, sid, _, _, err := smb2ConnectAndNegotiate(host, port, build)
			if err != nil {
				continue
			}
			var preauth []byte
			ch, sid2, err := smb2RequestNTLMChallenge(c, sid, 1, blobFn(), &preauth)
			if err != nil {
				c.Close()
				continue
			}
			return c, ch, sid2, nil
		}
	}
	return nil, nil, 0, fmt.Errorf("no NTLM challenge")
}
