package smbvers

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

type smb1SessionInfo struct {
	NativeOS   string
	NativeLM   string
	Domain     string
	Server     string
	SystemTime string
}

// probeSMB1SessionOS performs SMB1 negotiate + guest session setup.
func probeSMB1SessionOS(host string, port int) *smb1SessionInfo {
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
	negoFrame, err := netbiosRead(conn)
	if err != nil {
		return nil
	}
	nego := smbPayload(negoFrame)
	tzMin, sysUTC := parseSMB1NegotiateTime(nego)
	if len(nego) >= 4 && nego[0] == 0xfe {
		return smb1SessionFromNTLM(host, port, tzMin, sysUTC)
	}

	extSec := false
	if len(nego) >= 12 {
		flags2 := binary.LittleEndian.Uint16(nego[10:12])
		extSec = flags2&0x0800 != 0
	}
	if extSec {
		return probeSMB1SessionExtended(host, port, tzMin, sysUTC)
	}

	req := buildSMB1SessionSetupAndX("")
	if err := netbiosWrite(conn, req); err != nil {
		return nil
	}
	respFrame, err := netbiosRead(conn)
	if err != nil {
		return nil
	}
	resp := smbPayload(respFrame)
	info := parseSMB1SessionSetupResponse(resp)
	if info == nil {
		return smb1SessionFromNTLM(host, port, tzMin, sysUTC)
	}
	if info.SystemTime == "" {
		info.SystemTime = formatSMBTime(sysUTC, tzMin)
	}
	return info
}

func smb1SessionFromNTLM(host string, port int, tzMin int16, sysUTC time.Time) *smb1SessionInfo {
	nt := probeNTLMTargetInfo(host, port)
	if nt == nil {
		return nil
	}
	out := &smb1SessionInfo{
		NativeOS:   nt.osVersion,
		NativeLM:   nt.lanManager,
		Domain:     nt.nbDomain,
		Server:     nt.nbComputer,
		SystemTime: probeSMB1Clock(host, port),
	}
	if out.SystemTime == "" {
		out.SystemTime = formatSMBTime(sysUTC, tzMin)
	}
	if nt.timestamp != "" && out.SystemTime == "" {
		out.SystemTime = nt.timestamp
	}
	if out.NativeOS == "" && out.NativeLM == "" && out.Server == "" {
		return nil
	}
	return out
}

func probeSMB1SessionExtended(host string, port int, tzMin int16, sysUTC time.Time) *smb1SessionInfo {
	conn, err := dial(host, port)
	if err != nil {
		return nil
	}
	defer conn.Close()
	if port == portNBSS {
		conn.Write(netbiosSessionRequest())
		ack := make([]byte, 4)
		io.ReadFull(conn, ack)
	}
	netbiosWrite(conn, buildSMB1NegotiateNTLM012())
	if _, err := netbiosRead(conn); err != nil {
		return nil
	}
	secBlob := wrapSPNEGONTLMNegotiate(buildNTLMNegotiate())
	if err := netbiosWrite(conn, buildSMB1SessionSetupExtSec(secBlob)); err != nil {
		return nil
	}
	respFrame, err := netbiosRead(conn)
	if err != nil {
		return nil
	}
	resp := smbPayload(respFrame)
	var nt *ntlmTarget
	if sec := smb1SecurityBlob(resp); len(sec) > 0 {
		if ch := findNTLMMessage(sec, 2); ch != nil {
			nt = parseNTLMChallengeTarget(ch)
		}
	}
	if nt == nil {
		nt = probeNTLMTargetInfo(host, port)
	}
	if nt == nil {
		out := &smb1SessionInfo{SystemTime: formatSMBTime(sysUTC, tzMin)}
		return out
	}
	out := &smb1SessionInfo{
		NativeOS:   nt.osVersion,
		NativeLM:   nt.lanManager,
		Domain:     nt.nbDomain,
		Server:     nt.nbComputer,
		SystemTime: formatSMBTime(sysUTC, tzMin),
	}
	if nt.timestamp != "" {
		out.SystemTime = nt.timestamp
	}
	return out
}

func buildSMB1SessionSetupExtSec(secBlob []byte) []byte {
	params := make([]byte, 24)
	binary.LittleEndian.PutUint16(params[0:2], 0xff00)
	binary.LittleEndian.PutUint16(params[4:6], 0xffff)
	binary.LittleEndian.PutUint16(params[6:8], 2)
	binary.LittleEndian.PutUint16(params[8:10], 1)
	binary.LittleEndian.PutUint16(params[14:16], uint16(len(secBlob)))

	hdr := make([]byte, 32)
	copy(hdr[0:4], []byte{0xff, 'S', 'M', 'B'})
	hdr[4] = 0x73
	binary.LittleEndian.PutUint16(hdr[10:12], 0xc807)

	body := append([]byte{12}, params...)
	body = append(body, u16(uint16(len(secBlob)))...)
	body = append(body, secBlob...)
	return append(hdr, body...)
}

func smb1SecurityBlob(pkt []byte) []byte {
	if len(pkt) < 36 || pkt[0] != 0xff || pkt[4] != 0x73 {
		return nil
	}
	st := binary.LittleEndian.Uint32(pkt[5:9])
	if st != 0 && st != stMoreProcessing {
		return nil
	}
	wc := int(pkt[32])
	off := 33 + wc*2
	if off+2 > len(pkt) {
		return nil
	}
	bc := int(binary.LittleEndian.Uint16(pkt[off : off+2]))
	off += 2
	if bc <= 0 || off+bc > len(pkt) {
		return nil
	}
	return pkt[off : off+bc]
}

func parseSMB1NegotiateTime(pkt []byte) (tzMin int16, sysUTC time.Time) {
	if len(pkt) < 36 || pkt[0] != 0xff || pkt[4] != 0x72 {
		return 0, time.Time{}
	}
	wc := int(pkt[32])
	if 33+wc*2 > len(pkt) {
		return 0, time.Time{}
	}
	params := pkt[33 : 33+wc*2]
	const sysTimeOff = 23
	const tzOff = 31
	if len(params) < tzOff+2 {
		return 0, time.Time{}
	}
	ft := binary.LittleEndian.Uint64(params[sysTimeOff : sysTimeOff+8])
	rawTZ := int16(binary.LittleEndian.Uint16(params[tzOff : tzOff+2]))
	tzMin = rawTZ
	if tzMin < 0 {
		tzMin = -tzMin
	}
	if tzMin > 14*60 {
		tzMin = 0
	}
	const epoch = 11644473600
	sec := int64(ft/10000000) - epoch
	if sec > 0 && sec < 2000000000 {
		sysUTC = time.Unix(sec, 0).UTC()
	}
	return tzMin, sysUTC
}

func smb1NegotiateTZ(host string, port int) int16 {
	conn, err := dial(host, port)
	if err != nil {
		return 0
	}
	defer conn.Close()
	if port == portNBSS {
		conn.Write(netbiosSessionRequest())
		ack := make([]byte, 4)
		io.ReadFull(conn, ack)
	}
	if err := netbiosWrite(conn, buildSMB1NegotiateNTLM012()); err != nil {
		return 0
	}
	resp, err := netbiosRead(conn)
	if err != nil {
		return 0
	}
	tz, _ := parseSMB1NegotiateTime(smbPayload(resp))
	return tz
}

func buildSMB1SessionSetupAndX(username string) []byte {
	acc := utf16LE(username + "\x00")
	dom := utf16LE("\x00")
	osField := utf16LE("Unix\x00")
	lm := utf16LE("Samba\x00")
	data := append(acc, dom...)
	data = append(data, osField...)
	data = append(data, lm...)

	params := make([]byte, 26)
	binary.LittleEndian.PutUint16(params[0:2], 0xff00)
	binary.LittleEndian.PutUint16(params[2:4], 0)
	binary.LittleEndian.PutUint16(params[4:6], 0xffff)
	binary.LittleEndian.PutUint16(params[6:8], 2)
	binary.LittleEndian.PutUint16(params[8:10], 1)
	binary.LittleEndian.PutUint32(params[10:14], 0)
	binary.LittleEndian.PutUint16(params[14:16], 0)
	binary.LittleEndian.PutUint16(params[16:18], 0)
	binary.LittleEndian.PutUint32(params[18:22], 0)
	binary.LittleEndian.PutUint32(params[22:26], 0x00000050)

	hdr := make([]byte, 32)
	copy(hdr[0:4], []byte{0xff, 'S', 'M', 'B'})
	hdr[4] = 0x73
	binary.LittleEndian.PutUint16(hdr[10:12], 0xc807)

	body := append([]byte{13}, params...)
	body = append(body, u16(uint16(len(data)))...)
	body = append(body, data...)
	return append(hdr, body...)
}

func utf16LE(s string) []byte {
	b := make([]byte, 0, len(s)*2)
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

func parseSMB1SessionSetupResponse(pkt []byte) *smb1SessionInfo {
	if len(pkt) < 36 || pkt[0] != 0xff || pkt[4] != 0x73 {
		return nil
	}
	status := binary.LittleEndian.Uint32(pkt[5:9])
	if status != 0 && status != 0xc000006d {
		return nil
	}
	wc := int(pkt[32])
	off := 33 + wc*2
	if off+2 > len(pkt) {
		return nil
	}
	bc := int(binary.LittleEndian.Uint16(pkt[off : off+2]))
	off += 2
	if bc <= 0 || off+bc > len(pkt) {
		return nil
	}
	data := pkt[off : off+bc]
	unicode := binary.LittleEndian.Uint16(pkt[10:12])&0x8000 != 0
	info := extractSMB1SessionOS(data, unicode)
	if info == nil {
		return nil
	}
	return info
}

func extractSMB1SessionOS(data []byte, unicode bool) *smb1SessionInfo {
	strs := smb1DataStrings(data, unicode)
	info := &smb1SessionInfo{}
	for _, st := range strs {
		st = strings.TrimSpace(st)
		if st == "" {
			continue
		}
		if strings.Contains(st, "Windows") {
			if info.NativeOS == "" {
				info.NativeOS = st
			} else if info.NativeLM == "" {
				info.NativeLM = st
			}
			continue
		}
		if info.Domain == "" && len(st) < 64 {
			info.Domain = st
		}
	}
	if info.NativeOS == "" && info.NativeLM == "" {
		return nil
	}
	if info.NativeLM == "" && len(strs) >= 2 {
		info.NativeLM = strings.TrimSpace(strs[1])
	}
	if info.NativeOS == "" && len(strs) >= 1 {
		info.NativeOS = strings.TrimSpace(strs[0])
	}
	if !looksLikeOSString(info.NativeOS) && !looksLikeOSString(info.NativeLM) {
		return nil
	}
	return info
}

func formatSMBTime(utc time.Time, tzMinutes int16) string {
	if utc.IsZero() {
		return ""
	}
	if tzMinutes <= 0 || tzMinutes > 14*60 {
		return utc.Format("2006-01-02T15:04:05Z07:00")
	}
	// SMB ServerTimeZone: minutes the server is behind UTC.
	hours := -float64(tzMinutes) / 60.0
	offsetSec := int(hours * 3600)
	loc := time.FixedZone(formatTZName(hours), offsetSec)
	return utc.In(loc).Format("2006-01-02T15:04:05-07:00")
}

func formatTZName(hours float64) string {
	if hours == 0 {
		return "UTC"
	}
	if hours > 0 {
		return fmt.Sprintf("UTC+%g", hours)
	}
	return fmt.Sprintf("UTC%g", hours)
}

func probeSMB1Clock(host string, port int) string {
	tz := smb1NegotiateTZ(host, port)
	if s2, err := negotiateSMB2(host, port, buildSMB2Negotiate202); err == nil && !s2.SystemTimeUTC.IsZero() {
		return formatSMBTime(s2.SystemTimeUTC, tz)
	}
	conn, err := dial(host, port)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if port == portNBSS {
		conn.Write(netbiosSessionRequest())
		ack := make([]byte, 4)
		io.ReadFull(conn, ack)
	}
	if err := netbiosWrite(conn, buildSMB1NegotiateNTLM012()); err != nil {
		return ""
	}
	resp, err := netbiosRead(conn)
	if err != nil {
		return ""
	}
	tz2, utc := parseSMB1NegotiateTime(smbPayload(resp))
	if tz != 0 {
		tz2 = tz
	}
	return formatSMBTime(utc, tz2)
}
