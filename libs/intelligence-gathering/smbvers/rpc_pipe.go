package smbvers

import "fmt"

type boundPipe struct {
	fid fileID
	rpc *rpcClient
}

func (s *SMBSession) bindPipe(name string, uuid [16]byte, ver uint32) (*boundPipe, error) {
	fid, err := s.openPipe(name)
	if err != nil {
		return nil, err
	}
	rpc := newRPCClient()
	if err := rpc.bind(s, fid, uuid, ver); err != nil {
		s.closeFile(fid)
		return nil, err
	}
	return &boundPipe{fid: fid, rpc: rpc}, nil
}

func (s *SMBSession) rpcOnPipe(name string, uuid [16]byte, ver uint32, opnum uint16, stub []byte) ([]byte, error) {
	bp, err := s.bindPipe(name, uuid, ver)
	if err != nil {
		return nil, err
	}
	defer s.closeFile(bp.fid)
	return bp.rpc.request(s, bp.fid, opnum, stub)
}

func (s *SMBSession) samrRPC() (*boundPipe, error) {
	if s.samr != nil {
		return s.samr, nil
	}
	bp, err := s.bindPipe("samr", uuidSAMR, rpcVersionMajorMinor(1, 0))
	if err != nil {
		return nil, fmt.Errorf("samr bind: %w", err)
	}
	s.samr = bp
	return bp, nil
}

func (s *SMBSession) srvsRPC() (*boundPipe, error) {
	if s.srvs != nil {
		return s.srvs, nil
	}
	bp, err := s.bindPipe("srvsvc", uuidSRVS, rpcVersionMajorMinor(3, 0))
	if err != nil {
		return nil, fmt.Errorf("srvsvc bind: %w", err)
	}
	s.srvs = bp
	return bp, nil
}

func (s *SMBSession) samrCall(opnum uint16, stub []byte) ([]byte, error) {
	bp, err := s.samrRPC()
	if err != nil {
		return nil, err
	}
	return bp.rpc.request(s, bp.fid, opnum, stub)
}

func (s *SMBSession) srvsCall(opnum uint16, stub []byte) ([]byte, error) {
	bp, err := s.srvsRPC()
	if err != nil {
		return nil, err
	}
	return bp.rpc.request(s, bp.fid, opnum, stub)
}

func (s *SMBSession) spoolRPC() (*boundPipe, error) {
	bp, err := s.bindPipe("spoolss", uuidSPOOL, rpcVersionMajorMinor(1, 0))
	if err != nil {
		return nil, fmt.Errorf("spoolss bind: %w", err)
	}
	return bp, nil
}

func (s *SMBSession) spoolCall(opnum uint16, stub []byte) ([]byte, error) {
	bp, err := s.spoolRPC()
	if err != nil {
		return nil, err
	}
	defer s.closeFile(bp.fid)
	return bp.rpc.request(s, bp.fid, opnum, stub)
}
