package smbvers

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

type ndrWriter struct {
	b []byte
}

func newNDRWriter() *ndrWriter { return &ndrWriter{} }

func (w *ndrWriter) bytes() []byte { return w.b }

func (w *ndrWriter) align(n int) {
	pad := (n - (len(w.b) % n)) % n
	if pad > 0 {
		w.b = append(w.b, make([]byte, pad)...)
	}
}

func (w *ndrWriter) u32(v uint32) {
	w.b = append(w.b, u32(v)...)
}

func (w *ndrWriter) u16(v uint16) {
	w.b = append(w.b, u16(v)...)
}

func (w *ndrWriter) rpcUnicodeString(s string) {
	chars := utf16.Encode([]rune(s))
	byteLen := uint16(len(chars) * 2)
	w.u16(byteLen)
	w.u16(byteLen + 2)
	if len(chars) == 0 {
		w.u32(0)
		return
	}
	w.u32(0x20000)
	max := uint32(len(chars) + 1)
	w.u32(max)
	w.u32(0)
	w.u32(max - 1)
	w.align(2)
	for _, c := range chars {
		w.u16(c)
	}
	w.u16(0)
}

func (w *ndrWriter) uniqueWString(s string) {
	if s == "" {
		w.u32(0)
		return
	}
	w.u32(0x20000) // referent id
	chars := utf16.Encode([]rune(s))
	max := uint32(len(chars) + 1) // includes NUL
	w.u32(max)
	w.u32(0)
	w.u32(max) // actual includes NUL
	w.align(2)
	for _, c := range chars {
		w.u16(c)
	}
	w.u16(0)
}

func (w *ndrWriter) contextHandle() {
	w.u32(0)
	w.b = append(w.b, make([]byte, 16)...)
}

type ndrReader struct {
	data []byte
	off  int
}

func newNDRReader(data []byte) *ndrReader {
	return &ndrReader{data: data}
}

func (r *ndrReader) align(n int) {
	pad := (n - (r.off % n)) % n
	r.off += pad
}

func (r *ndrReader) u32() (uint32, bool) {
	if r.off+4 > len(r.data) {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(r.data[r.off : r.off+4])
	r.off += 4
	return v, true
}

func (r *ndrReader) u16() (uint16, bool) {
	if r.off+2 > len(r.data) {
		return 0, false
	}
	v := binary.LittleEndian.Uint16(r.data[r.off : r.off+2])
	r.off += 2
	return v, true
}

func (r *ndrReader) readContextHandle() bool {
	if r.off+20 > len(r.data) {
		return false
	}
	r.off += 20
	return true
}

func (r *ndrReader) readDeferredWString() (string, bool) {
	maxCount, ok := r.u32()
	if !ok {
		return "", false
	}
	_, ok = r.u32() // offset
	if !ok {
		return "", false
	}
	actual, ok := r.u32()
	if !ok {
		return "", false
	}
	_ = maxCount
	r.align(2)
	if actual == 0 {
		return "", true
	}
	if r.off+int(actual)*2 > len(r.data) {
		return "", false
	}
	runes := make([]rune, 0, actual)
	for i := uint32(0); i < actual; i++ {
		c, ok := r.u16()
		if !ok {
			return "", false
		}
		if c == 0 {
			continue
		}
		runes = append(runes, rune(c))
	}
	r.align(4)
	return string(runes), true
}

func (r *ndrReader) readRPCUnicodeHeader() (length uint16, pointer uint32, ok bool) {
	length, ok = r.u16()
	if !ok {
		return 0, 0, false
	}
	_, ok = r.u16() // maximum length
	if !ok {
		return 0, 0, false
	}
	r.align(4)
	pointer, ok = r.u32()
	return length, pointer, ok
}

func (r *ndrReader) readConformantVaryingWString() (string, bool) {
	ref, ok := r.u32()
	if !ok {
		return "", false
	}
	if ref == 0 {
		return "", true
	}
	return r.readDeferredWString()
}

func (r *ndrReader) readSIDRaw() (raw []byte, display string, ok bool) {
	if r.off+8 > len(r.data) {
		return nil, "", false
	}
	rev := r.data[r.off]
	cnt := r.data[r.off+1]
	auth := make([]byte, 6)
	copy(auth, r.data[r.off+2:r.off+8])
	r.off += 8
	raw = append([]byte{rev, cnt}, auth...)
	for i := 0; i < int(cnt); i++ {
		v, ok2 := r.u32()
		if !ok2 {
			return nil, "", false
		}
		raw = append(raw, u32(v)...)
	}
	return raw, formatSID(raw), true
}

func formatSID(raw []byte) string {
	if len(raw) < 8 {
		return ""
	}
	rev := raw[0]
	cnt := int(raw[1])
	auth := raw[2:8]
	var idAuth uint64
	if auth[0] == 0 && auth[1] == 0 {
		idAuth = uint64(binary.BigEndian.Uint32(auth[2:6]))
	} else {
		for i := 0; i < 6; i++ {
			idAuth = (idAuth << 8) | uint64(auth[i])
		}
	}
	out := fmt.Sprintf("S-%d-%d", rev, idAuth)
	off := 8
	for i := 0; i < cnt && off+4 <= len(raw); i++ {
		out += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(raw[off:off+4]))
		off += 4
	}
	return out
}

func (w *ndrWriter) sid(raw []byte) {
	if len(raw) < 8 {
		return
	}
	cnt := uint32(raw[1])
	w.u32(cnt) // NDR conformant array max count for SubAuthority
	w.b = append(w.b, raw...)
	w.align(4)
}

func decodeRIDEnumBuffer(data []byte) ([]ridName, error) {
	r := newNDRReader(data)
	ref, ok := r.u32()
	if !ok || ref == 0 {
		return nil, nil
	}
	entries, ok := r.u32()
	if !ok {
		return nil, nil
	}
	ref2, ok := r.u32()
	if !ok || ref2 == 0 {
		return nil, nil
	}
	max, ok := r.u32()
	if !ok {
		return nil, nil
	}
	if max < entries {
		entries = max
	}
	type meta struct {
		rid    uint32
		nameLen uint16
		namePtr uint32
	}
	metas := make([]meta, 0, entries)
	for i := uint32(0); i < entries; i++ {
		rid, ok := r.u32()
		if !ok {
			break
		}
		nameLen, namePtr, ok := r.readRPCUnicodeHeader()
		if !ok {
			break
		}
		metas = append(metas, meta{rid: rid, nameLen: nameLen, namePtr: namePtr})
	}
	var out []ridName
	for _, m := range metas {
		name := ""
		if m.namePtr != 0 {
			if s, ok := r.readDeferredWString(); ok {
				name = s
			}
		}
		out = append(out, ridName{RID: m.rid, Name: name})
	}
	return out, nil
}

type ridName struct {
	RID  uint32
	Name string
}
