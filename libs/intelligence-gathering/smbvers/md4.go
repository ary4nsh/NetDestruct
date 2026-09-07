package smbvers

import (
	"hash"
	"math/bits"
)

const (
	md4Chunk  = 64
	md4Init0  = 0x67452301
	md4Init1  = 0xefcdab89
	md4Init2  = 0x98badcfe
	md4Init3  = 0x10325476
	md4Size   = 16
)

// md4Digest implements RFC 1320 MD4 for NTLM (Go stdlib only).
type md4Digest struct {
	s   [4]uint32
	x   [md4Chunk]byte
	nx  int
	len uint64
}

func md4New() hash.Hash {
	d := new(md4Digest)
	d.Reset()
	return d
}

func (d *md4Digest) Reset() {
	d.s[0], d.s[1], d.s[2], d.s[3] = md4Init0, md4Init1, md4Init2, md4Init3
	d.nx = 0
	d.len = 0
}

func (d *md4Digest) Size() int       { return md4Size }
func (d *md4Digest) BlockSize() int { return md4Chunk }

func (d *md4Digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := len(p)
		if n > md4Chunk-d.nx {
			n = md4Chunk - d.nx
		}
		copy(d.x[d.nx:], p[:n])
		d.nx += n
		if d.nx == md4Chunk {
			md4Block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	n := md4Block(d, p)
	p = p[n:]
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d0 *md4Digest) Sum(in []byte) []byte {
	d := new(md4Digest)
	*d = *d0
	length := d.len
	var tmp [64]byte
	tmp[0] = 0x80
	if length%64 < 56 {
		d.Write(tmp[:56-length%64])
	} else {
		d.Write(tmp[:64+56-length%64])
	}
	length <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(length >> (8 * i))
	}
	d.Write(tmp[:8])
	for _, s := range d.s {
		in = append(in, byte(s), byte(s>>8), byte(s>>16), byte(s>>24))
	}
	return in
}

var (
	md4Shift1  = []int{3, 7, 11, 19}
	md4Shift2  = []int{3, 5, 9, 13}
	md4Shift3  = []int{3, 9, 11, 15}
	md4Index2  = []uint{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
	md4Index3  = []uint{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
)

func md4Block(dig *md4Digest, p []byte) int {
	a, b, c, dd := dig.s[0], dig.s[1], dig.s[2], dig.s[3]
	n := 0
	var X [16]uint32
	for len(p) >= md4Chunk {
		aa, bb, cc, ddd := a, b, c, dd
		for i := 0; i < 16; i++ {
			j := i * 4
			X[i] = uint32(p[j]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
		}
		for i := uint(0); i < 16; i++ {
			f := ((c ^ dd) & b) ^ dd
			a += f + X[i]
			a = bits.RotateLeft32(a, md4Shift1[i%4])
			a, b, c, dd = dd, a, b, c
		}
		for i := uint(0); i < 16; i++ {
			g := (b & c) | (b & dd) | (c & dd)
			a += g + X[md4Index2[i]] + 0x5a827999
			a = bits.RotateLeft32(a, md4Shift2[i%4])
			a, b, c, dd = dd, a, b, c
		}
		for i := uint(0); i < 16; i++ {
			h := b ^ c ^ dd
			a += h + X[md4Index3[i]] + 0x6ed9eba1
			a = bits.RotateLeft32(a, md4Shift3[i%4])
			a, b, c, dd = dd, a, b, c
		}
		a += aa
		b += bb
		c += cc
		dd += ddd
		p = p[md4Chunk:]
		n += md4Chunk
	}
	dig.s[0], dig.s[1], dig.s[2], dig.s[3] = a, b, c, dd
	return n
}
