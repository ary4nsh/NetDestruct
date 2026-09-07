package smbvers

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const (
	rpcVersion     = 5
	rpcVersionMinor = 0
	rpcBind        = 11
	rpcBindAck     = 12
	rpcRequest     = 0
	rpcResponse    = 2

	rpcFirstFrag = 0x01
	rpcLastFrag  = 0x02

	ndrTransferUUID = "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60"
)

type rpcClient struct {
	callID    uint32
	contextID uint16
}

func newRPCClient() *rpcClient {
	return &rpcClient{callID: 1, contextID: 0}
}

func uuidLE(u [16]byte) []byte {
	return u[:]
}

var (
	uuidSAMR  = [16]byte{0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac}
	uuidSRVS  = [16]byte{0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88}
	uuidSPOOL = [16]byte{0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}
)

func rpcVersionMajorMinor(major, minor uint16) uint32 {
	return (uint32(major) << 16) | uint32(minor)
}

func (r *rpcClient) bind(s *SMBSession, fid fileID, ifaceUUID [16]byte, ifaceVer uint32) error {
	major := uint16(ifaceVer >> 16)
	minor := uint16(ifaceVer)
	if major == 0 && minor == 0 {
		major, minor = 1, 0
	}

	pkt := make([]byte, 72)
	pkt[0] = rpcVersion
	pkt[1] = rpcVersionMinor
	pkt[2] = rpcBind
	pkt[3] = rpcFirstFrag | rpcLastFrag
	pkt[4] = 0x10
	binary.LittleEndian.PutUint16(pkt[8:10], 72)
	binary.LittleEndian.PutUint32(pkt[12:16], r.callID)
	binary.LittleEndian.PutUint16(pkt[16:18], 4280)
	binary.LittleEndian.PutUint16(pkt[18:20], 4280)
	binary.LittleEndian.PutUint32(pkt[24:28], 1)
	binary.LittleEndian.PutUint16(pkt[28:30], r.contextID)
	binary.LittleEndian.PutUint16(pkt[30:32], 1)
	copy(pkt[32:48], uuidLE(ifaceUUID))
	binary.LittleEndian.PutUint16(pkt[48:50], major)
	binary.LittleEndian.PutUint16(pkt[50:52], minor)
	copy(pkt[52:68], ndrTransferUUID)
	binary.LittleEndian.PutUint32(pkt[68:72], 2)

	resp, err := s.pipeTransact(fid, pkt)
	if err != nil {
		return err
	}
	if len(resp) < 16 {
		return fmt.Errorf("short bind response")
	}
	if resp[2] != rpcBindAck {
		return fmt.Errorf("unexpected rpc packet type %d", resp[2])
	}
	if result, ok := parseBindAckResult(resp); ok && result != 0 {
		return fmt.Errorf("bind rejected result %d", result)
	}
	r.callID++
	return nil
}

func parseBindAckResult(resp []byte) (uint16, bool) {
	if len(resp) < 48 || resp[2] != rpcBindAck {
		return 0, false
	}
	off := 24
	if off+2 > len(resp) {
		return 0, false
	}
	secLen := int(binary.LittleEndian.Uint16(resp[off : off+2]))
	off += 2 + secLen
	for off%4 != 0 {
		off++
	}
	if off+4 > len(resp) || resp[off] != 1 {
		return 0, false
	}
	off += 4
	if off+2 > len(resp) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(resp[off : off+2]), true
}

func (r *rpcClient) request(s *SMBSession, fid fileID, opnum uint16, stub []byte) ([]byte, error) {
	pkt := make([]byte, 24+len(stub))
	pkt[0] = rpcVersion
	pkt[1] = rpcVersionMinor
	pkt[2] = rpcRequest
	pkt[3] = rpcFirstFrag | rpcLastFrag
	pkt[4] = 0x10
	binary.LittleEndian.PutUint32(pkt[12:16], r.callID)
	binary.LittleEndian.PutUint16(pkt[20:22], r.contextID)
	binary.LittleEndian.PutUint16(pkt[22:24], opnum)
	copy(pkt[24:], stub)
	binary.LittleEndian.PutUint16(pkt[8:10], uint16(len(pkt)))
	binary.LittleEndian.PutUint32(pkt[16:20], uint32(len(stub)))

	resp, err := s.pipeTransact(fid, pkt)
	if err != nil {
		return nil, err
	}
	r.callID++
	if len(resp) < 28 {
		return nil, fmt.Errorf("short rpc response")
	}
	if resp[2] == 3 { // fault
		return nil, fmt.Errorf("rpc fault status 0x%08x", binary.LittleEndian.Uint32(resp[24:28]))
	}
	if resp[2] != rpcResponse {
		return nil, fmt.Errorf("unexpected rpc response type %d (payload %s)", resp[2], hex.EncodeToString(resp[:min(32, len(resp))]))
	}
	if len(resp) <= 24 {
		return nil, nil
	}
	return resp[24:], nil
}

func (r *rpcClient) buildHeader(ptype byte, flags byte, authLen uint16) []byte {
	h := make([]byte, 16)
	h[0] = rpcVersion
	h[1] = rpcVersionMinor
	h[2] = ptype
	h[3] = flags
	binary.LittleEndian.PutUint16(h[4:6], 0x0010)
	binary.LittleEndian.PutUint16(h[10:12], authLen)
	binary.LittleEndian.PutUint32(h[12:16], r.callID)
	return h
}
