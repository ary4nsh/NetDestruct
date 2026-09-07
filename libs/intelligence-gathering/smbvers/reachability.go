package smbvers

import "fmt"

// CheckSMBPort verifies TCP reachability and SMB2 negotiate on the target.
func CheckSMBPort(host string, port int) error {
	if port <= 0 {
		port = portDirect
	}
	builds := []func() []byte{buildSMB2Negotiate202, buildSMB2NegotiateLegacy, buildSMB2Negotiate311}
	var lastErr error
	for _, build := range builds {
		conn, err := dial(host, port)
		if err != nil {
			return fmt.Errorf("tcp dial %s:%d: %w", host, port, err)
		}
		if err := netbiosPreamble(conn, port); err != nil {
			conn.Close()
			lastErr = err
			continue
		}
		if err := netbiosWrite(conn, build()); err != nil {
			conn.Close()
			lastErr = err
			continue
		}
		resp, err := netbiosRead(conn)
		conn.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if _, err := parseSMB2NegotiateResponse(resp); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("smb negotiate with %s:%d: %w", host, port, lastErr)
	}
	return fmt.Errorf("smb negotiate with %s:%d failed", host, port)
}
