package smbvers

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

const smb2FlagsSigned = 0x0008

func deriveSigningKey(sessionKey []byte, dialect uint16, preauth []byte, signingRequired bool) []byte {
	if len(sessionKey) == 0 || !signingRequired {
		return sessionKey
	}
	if dialect >= 0x0311 {
		ctx := preauth
		if len(ctx) == 0 {
			ctx = make([]byte, 64)
		}
		return smb2KDF(sessionKey, []byte("SMBSigningKey\x00"), ctx, 16)
	}
	if dialect >= 0x0300 {
		return smb2KDF(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"), 16)
	}
	return sessionKey
}

func smb2KDF(key, label, context []byte, outLen int) []byte {
	lBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lBuf, uint32(outLen*8))
	out := make([]byte, 0, outLen)
	for i := 1; len(out) < outLen; i++ {
		ib := make([]byte, 4)
		binary.BigEndian.PutUint32(ib, uint32(i))
		h := hmac.New(sha256.New, key)
		h.Write(ib)
		h.Write(label)
		h.Write([]byte{0})
		h.Write(context)
		h.Write(lBuf)
		out = append(out, h.Sum(nil)...)
	}
	return out[:outLen]
}

func signSMB2Packet(pkt []byte, signingKey []byte, dialect uint16) {
	if len(signingKey) == 0 {
		return
	}
	flags := binary.LittleEndian.Uint16(pkt[16:18])
	binary.LittleEndian.PutUint16(pkt[16:18], flags|smb2FlagsSigned)
	for i := 48; i < 64; i++ {
		pkt[i] = 0
	}
	var sig []byte
	if dialect >= 0x0300 {
		sig = aesCMAC(signingKey, pkt)
	} else {
		mac := hmac.New(sha256.New, signingKey)
		mac.Write(pkt)
		sig = mac.Sum(nil)[:16]
	}
	copy(pkt[48:64], sig)
}

func aesCMAC(key, msg []byte) []byte {
	const bs = 16
	k1, k2 := aesCMACSubkeys(key)
	n := len(msg) / bs
	var lastComplete bool
	if n == 0 {
		n = 1
		lastComplete = false
	} else if len(msg)%bs == 0 {
		lastComplete = true
	} else {
		n++
		lastComplete = false
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return make([]byte, 16)
	}

	x := make([]byte, bs)
	for i := 0; i < n-1; i++ {
		xorBlock(x, msg[i*bs:(i+1)*bs])
		block.Encrypt(x, x)
	}

	var mLast []byte
	if lastComplete {
		mLast = xorBytes(msg[(n-1)*bs:n*bs], k1)
	} else {
		mLast = xorBytes(padCMAC(msg[(n-1)*bs:]), k2)
	}
	y := xorBytes(mLast, x)
	t := make([]byte, bs)
	block.Encrypt(t, y)
	return t
}

func aesCMACSubkeys(key []byte) (k1, k2 []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return make([]byte, 16), make([]byte, 16)
	}
	l := make([]byte, 16)
	block.Encrypt(l, l)

	high := binary.BigEndian.Uint64(l[0:8])
	low := binary.BigEndian.Uint64(l[8:16])

	k1High := ((high << 1) | (low >> 63)) & 0xffffffffffffffff
	k1Low := (low << 1) & 0xffffffffffffffff
	if high>>63 != 0 {
		k1Low ^= 0x87
	}

	k2High := ((k1High << 1) | (k1Low >> 63)) & 0xffffffffffffffff
	k2Low := (k1Low << 1) & 0xffffffffffffffff
	if k1High>>63 != 0 {
		k2Low ^= 0x87
	}

	k1 = make([]byte, 16)
	k2 = make([]byte, 16)
	binary.BigEndian.PutUint64(k1[0:8], k1High)
	binary.BigEndian.PutUint64(k1[8:16], k1Low)
	binary.BigEndian.PutUint64(k2[0:8], k2High)
	binary.BigEndian.PutUint64(k2[8:16], k2Low)
	return k1, k2
}

func padCMAC(b []byte) []byte {
	out := make([]byte, 16)
	copy(out, b)
	out[len(b)] = 0x80
	return out
}

func xorBlock(dst, src []byte) {
	for i := 0; i < len(dst) && i < len(src); i++ {
		dst[i] ^= src[i]
	}
}

func xorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}
