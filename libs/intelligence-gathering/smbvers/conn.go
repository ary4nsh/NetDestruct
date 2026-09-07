package smbvers

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"time"
)

const connTimeout = 8 * time.Second

func netbiosWrite(conn net.Conn, msg []byte) error {
	if len(msg) > 0x00ffffff {
		return fmt.Errorf("message too large")
	}
	frame := make([]byte, 4+len(msg))
	frame[0] = 0x00
	frame[1] = byte(len(msg) >> 16)
	frame[2] = byte(len(msg) >> 8)
	frame[3] = byte(len(msg))
	copy(frame[4:], msg)
	_, err := conn.Write(frame)
	return err
}

// netbiosRead returns the 4-byte session header plus SMB payload (pkt[4] is SMB2/1).
func netbiosRead(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	length := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if length <= 0 || length > 256*1024 {
		return nil, fmt.Errorf("invalid netbios length %d", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

func netbiosSessionRequest() []byte {
	called := encodeNetBIOSName("*SMBSERVER")
	calling := encodeNetBIOSName("NETDESTRUCT")
	payloadLen := len(called) + len(calling) + 1
	b := make([]byte, 0, 4+payloadLen)
	b = append(b, 0x81)
	b = append(b, byte(payloadLen>>8), byte(payloadLen))
	b = append(b, called...)
	b = append(b, calling...)
	b = append(b, 0x00)
	return b
}

func encodeNetBIOSName(name string) []byte {
	name = fmt.Sprintf("%-16.16s", name)
	out := make([]byte, 32)
	for i := 0; i < 16; i++ {
		c := name[i]
		out[i*2] = (c >> 4) + 'A'
		out[i*2+1] = (c & 0x0f) + 'A'
	}
	return out
}

func dial(host string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, connTimeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(connTimeout))
	return conn, nil
}

func negotiateSMB2(host string, port int, build func() []byte) (*smb2NegotiateResult, error) {
	conn, err := dial(host, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if port == portNBSS {
		if _, err := conn.Write(netbiosSessionRequest()); err != nil {
			return nil, err
		}
		ack := make([]byte, 4)
		if _, err := io.ReadFull(conn, ack); err != nil {
			return nil, err
		}
		if ack[0] != 0x82 {
			return nil, fmt.Errorf("netbios session rejected 0x%02x", ack[0])
		}
	}

	if err := netbiosWrite(conn, build()); err != nil {
		return nil, err
	}
	resp, err := netbiosRead(conn)
	if err != nil {
		return nil, err
	}
	return parseSMB2NegotiateResponse(resp)
}

func probeSMB1(host string, port int) *smb1NegotiateResult {
	conn, err := dial(host, port)
	if err != nil {
		return nil
	}
	defer conn.Close()

	if port == portNBSS {
		if _, err := conn.Write(netbiosSessionRequest()); err != nil {
			return nil
		}
		ack := make([]byte, 4)
		if _, err := io.ReadFull(conn, ack); err != nil || ack[0] != 0x82 {
			return nil
		}
	}
	if err := netbiosWrite(conn, buildSMB1NegotiateNTLM012()); err != nil {
		return nil
	}
	resp, err := netbiosRead(conn)
	if err != nil {
		return nil
	}
	s1, err := parseSMB1NegotiateResponse(smbPayload(resp))
	if err != nil {
		return nil
	}
	return s1
}

func smbPayload(frame []byte) []byte {
	if len(frame) >= 5 && frame[0] == 0 && (frame[4] == 0xff || frame[4] == 0xfe) {
		return frame[4:]
	}
	return frame
}

type hostScanResult struct {
	Port int
	SMB2 *smb2NegotiateResult
	SMB1 *smb1NegotiateResult
	Probe dialectProbe
	OS    *smbOSDiscovery
}

func probeHost(ip net.IP, port int) (*hostScanResult, bool) {
	if port <= 0 {
		port = portDirect
	}
	host := ip.String()
	builders := []func() []byte{
		buildSMB2Negotiate202,
		buildSMB2NegotiateLegacy,
		buildSMB2Negotiate311,
	}
	var best *smb2NegotiateResult
	bestPort := 0
	for _, build := range builders {
		s2, err := negotiateSMB2(host, port, build)
		if err != nil {
			continue
		}
		if best == nil || s2.Dialect > best.Dialect {
			best = s2
			bestPort = port
		}
	}
	if best == nil {
		return nil, false
	}
	s1 := probeSMB1(host, bestPort)
	if full, err := negotiateSMB2(host, bestPort, buildSMB2Negotiate311); err == nil {
		if full.SystemTime != "" {
			best.SystemTime = full.SystemTime
			best.SystemTimeUTC = full.SystemTimeUTC
		}
		best.PreauthHashAlgs = full.PreauthHashAlgs
		best.PreauthSaltHex = full.PreauthSaltHex
		best.EncryptionAlgos = full.EncryptionAlgos
		best.SigningAlgos = full.SigningAlgos
		best.CompressionAlgos = full.CompressionAlgos
	}
	probe := probeSMBDialects(host, bestPort, best.Dialect)
	osdisc := discoverSMBOS(host, bestPort, s1, best)
	if osdisc != nil && osdisc.AuthDomain != "" {
		best.AuthDomain = osdisc.AuthDomain
	}
	return &hostScanResult{
		Port:  bestPort,
		SMB2:  best,
		SMB1:  s1,
		Probe: probe,
		OS:    osdisc,
	}, true
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
