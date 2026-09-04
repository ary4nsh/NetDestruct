package ssh

import (
	"crypto/sha512"
	"errors"

	"netdestruct/libs/authentication-cracking/ssh/blowfish"
)

const bcryptPBKDFBlockSize = 32

// bcryptPBKDF implements OpenBSD bcrypt_pbkdf (used by OpenSSH private keys).
// See golang.org/x/crypto/ssh/internal/bcrypt_pbkdf.
func bcryptPBKDF(password, salt, key []byte, rounds int) error {
	if rounds < 1 {
		return errors.New("bcrypt_pbkdf: number of rounds is too small")
	}
	if len(password) == 0 {
		return errors.New("bcrypt_pbkdf: empty password")
	}
	if len(salt) == 0 || len(salt) > 1<<20 {
		return errors.New("bcrypt_pbkdf: bad salt length")
	}
	keyLen := len(key)
	if keyLen > 1024 {
		return errors.New("bcrypt_pbkdf: keyLen is too large")
	}

	numBlocks := (keyLen + bcryptPBKDFBlockSize - 1) / bcryptPBKDFBlockSize
	outKey := make([]byte, numBlocks*bcryptPBKDFBlockSize)

	h := sha512.New()
	h.Write(password)
	shapass := h.Sum(nil)

	shasalt := make([]byte, 0, sha512.Size)
	cnt, tmp := make([]byte, 4), make([]byte, bcryptPBKDFBlockSize)
	for block := 1; block <= numBlocks; block++ {
		h.Reset()
		h.Write(salt)
		cnt[0] = byte(block >> 24)
		cnt[1] = byte(block >> 16)
		cnt[2] = byte(block >> 8)
		cnt[3] = byte(block)
		h.Write(cnt)
		bcryptHash(tmp, shapass, h.Sum(shasalt))

		out := make([]byte, bcryptPBKDFBlockSize)
		copy(out, tmp)
		for i := 2; i <= rounds; i++ {
			h.Reset()
			h.Write(tmp)
			bcryptHash(tmp, shapass, h.Sum(shasalt))
			for j := 0; j < len(out); j++ {
				out[j] ^= tmp[j]
			}
		}

		for i, v := range out {
			outKey[i*numBlocks+(block-1)] = v
		}
	}
	copy(key, outKey[:keyLen])
	return nil
}

var bcryptMagic = []byte("OxychromaticBlowfishSwatDynamite")

func bcryptHash(out, shapass, shasalt []byte) {
	c, err := blowfish.NewSaltedCipher(shapass, shasalt)
	if err != nil {
		panic(err)
	}
	for i := 0; i < 64; i++ {
		blowfish.ExpandKey(shasalt, c)
		blowfish.ExpandKey(shapass, c)
	}
	copy(out, bcryptMagic)
	for i := 0; i < 32; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(out[i:i+8], out[i:i+8])
		}
	}
	// Swap bytes due to different endianness.
	for i := 0; i < 32; i += 4 {
		out[i+3], out[i+2], out[i+1], out[i] = out[i], out[i+1], out[i+2], out[i+3]
	}
}
