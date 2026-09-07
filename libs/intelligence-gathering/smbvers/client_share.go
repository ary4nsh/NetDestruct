package smbvers

import (
	"encoding/binary"
	"fmt"
)

func (s *SMBSession) treeConnect(path string) (uint32, error) {
	pathU := utf16LE(path)
	body := make([]byte, 0, 8+len(pathU))
	body = append(body, u16(9)...)
	body = append(body, 0x00, 0x00)
	off := uint16(64 + 8)
	body = append(body, u16(off)...)
	body = append(body, u16(uint16(len(pathU)))...)
	body = append(body, pathU...)

	s.refreshDeadline()
	hdr := smb2RequestHeader(smb2CmdTreeConnect, s.nextMsg())
	smb2PutSessionID(hdr, s.sessionID)
	if err := s.writeSMB(append(hdr, body...)); err != nil {
		return 0, err
	}
	resp, err := netbiosRead(s.conn)
	if err != nil {
		return 0, err
	}
	st := smb2Status(resp)
	if st != stSuccess {
		return 0, fmt.Errorf("tree connect %q status 0x%08x", path, st)
	}
	off2 := smb2Offset(resp)
	if off2 < 0 || len(resp) < off2+64+8 {
		return 0, fmt.Errorf("short tree connect response")
	}
	return binary.LittleEndian.Uint32(resp[off2+36 : off2+40]), nil
}

func (s *SMBSession) treeDisconnect(treeID uint32) {
	body := make([]byte, 4)
	binary.LittleEndian.PutUint16(body[0:2], 4)
	hdr := smb2RequestHeader(0x0004, s.nextMsg()) // TreeDisconnect
	smb2PutSessionID(hdr, s.sessionID)
	smb2PutTreeID(hdr, treeID)
	_ = s.writeSMB(append(hdr, body...))
	_, _ = netbiosRead(s.conn)
}

func (s *SMBSession) openDirectory(treeID uint32, name string) (fileID, error) {
	nameU := utf16LE(name)
	const fixed = 56
	body := make([]byte, fixed+len(nameU))
	binary.LittleEndian.PutUint16(body[0:2], 57)
	body[2] = 0
	binary.LittleEndian.PutUint32(body[4:8], 2)
	binary.LittleEndian.PutUint32(body[24:28], fileListDirectory|fileTraverse|synchronizeAccess)
	binary.LittleEndian.PutUint32(body[32:36], fileShareReadWrite)
	binary.LittleEndian.PutUint32(body[36:40], fileOpen)
	binary.LittleEndian.PutUint32(body[40:44], fileDirectoryFile)
	nameOff := uint16(64 + fixed)
	binary.LittleEndian.PutUint16(body[44:46], nameOff)
	binary.LittleEndian.PutUint16(body[46:48], uint16(len(nameU)))
	copy(body[fixed:], nameU)

	s.refreshDeadline()
	hdr := smb2RequestHeader(smb2CmdCreate, s.nextMsg())
	smb2PutSessionID(hdr, s.sessionID)
	smb2PutTreeID(hdr, treeID)
	if err := s.writeSMB(append(hdr, body...)); err != nil {
		return fileID{}, err
	}
	resp, err := netbiosRead(s.conn)
	if err != nil {
		return fileID{}, err
	}
	st := smb2Status(resp)
	if st != stSuccess {
		return fileID{}, fmt.Errorf("open directory %q status 0x%08x", name, st)
	}
	off := smb2Offset(resp)
	if off < 0 || len(resp) < off+128+16 {
		return fileID{}, fmt.Errorf("short create response")
	}
	var fid fileID
	copy(fid[:], resp[off+128:off+144])
	return fid, nil
}

func (s *SMBSession) queryDirectory(treeID uint32, fid fileID) error {
	const bodyFixed = 33
	pattern := utf16LE("*")
	body := make([]byte, bodyFixed+len(pattern))
	binary.LittleEndian.PutUint16(body[0:2], 33)
	body[2] = fileDirectoryInfo
	body[3] = 0
	copy(body[16:32], fid[:])
	nameOff := uint16(64 + bodyFixed)
	binary.LittleEndian.PutUint16(body[32:34], nameOff)
	binary.LittleEndian.PutUint16(body[34:36], uint16(len(pattern)))
	binary.LittleEndian.PutUint32(body[36:40], 65536)
	copy(body[bodyFixed:], pattern)

	s.refreshDeadline()
	hdr := smb2RequestHeader(smb2CmdQueryDirectory, s.nextMsg())
	smb2PutSessionID(hdr, s.sessionID)
	smb2PutTreeID(hdr, treeID)
	if err := s.writeSMB(append(hdr, body...)); err != nil {
		return err
	}
	resp, err := netbiosRead(s.conn)
	if err != nil {
		return err
	}
	st := smb2Status(resp)
	if st != stSuccess {
		return fmt.Errorf("query directory status 0x%08x", st)
	}
	return nil
}

func (s *SMBSession) closeFileOnTree(treeID uint32, fid fileID) {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 24)
	copy(body[8:24], fid[:])
	hdr := smb2RequestHeader(smb2CmdClose, s.nextMsg())
	smb2PutSessionID(hdr, s.sessionID)
	smb2PutTreeID(hdr, treeID)
	_ = s.writeSMB(append(hdr, body...))
	_, _ = netbiosRead(s.conn)
}

func utf16LEPath(host, share string) string {
	return fmt.Sprintf(`\\%s\%s`, host, share)
}
