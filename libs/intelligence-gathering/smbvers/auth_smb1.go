package smbvers

import (
	"encoding/binary"
	"fmt"
)

func tryLoginSMB1(host string, port int, user, pass, domain string) (LoginOutcome, error) {
	blobs := [][]byte{
		wrapSPNEGONTLMNegotiate(buildNTLMNegotiate()),
		buildNTLMNegotiate(),
	}
	var lastErr error
	for _, blob := range blobs {
		out, err := smb1LoginOnce(host, port, user, pass, domain, blob)
		if err == nil {
			return out, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return LoginFail, lastErr
	}
	return LoginFail, fmt.Errorf("no NTLM challenge")
}

func smb1LoginOnce(host string, port int, user, pass, domain string, negotiateBlob []byte) (LoginOutcome, error) {
	conn, err := dial(host, port)
	if err != nil {
		return LoginFail, err
	}
	defer conn.Close()
	if err := netbiosPreamble(conn, port); err != nil {
		return LoginFail, err
	}
	if err := netbiosWrite(conn, buildSMB1NegotiateNTLM012()); err != nil {
		return LoginFail, err
	}
	if _, err := netbiosRead(conn); err != nil {
		return LoginFail, err
	}
	if err := netbiosWrite(conn, buildSMB1SessionSetupExtSec(negotiateBlob)); err != nil {
		return LoginFail, err
	}
	respFrame, err := netbiosRead(conn)
	if err != nil {
		return LoginFail, err
	}
	resp := smbPayload(respFrame)
	sec := smb1SecurityBlob(resp)
	chMsg := findNTLMMessage(sec, 2)
	if chMsg == nil {
		chMsg = findNTLMMessage(resp, 2)
	}
	if chMsg == nil {
		return LoginFail, fmt.Errorf("no NTLM challenge")
	}

	dom := loginDomainForNTLM(chMsg, domain)
	auth, _ := buildNTLMv2Authenticate(chMsg, user, pass, dom)
	if err := netbiosWrite(conn, buildSMB1SessionSetupExtSec(auth)); err != nil {
		return LoginFail, err
	}
	authFrame, err := netbiosRead(conn)
	if err != nil {
		return LoginFail, err
	}
	pkt := smbPayload(authFrame)
	if len(pkt) < 9 {
		return LoginFail, fmt.Errorf("short smb1 response")
	}
	st := binary.LittleEndian.Uint32(pkt[5:9])
	return mapLoginStatus(st), nil
}
