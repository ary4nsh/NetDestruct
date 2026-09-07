package smbvers

import (
	"crypto/sha512"
)

func newPreauthHash() []byte {
	return make([]byte, 64)
}

func updatePreauthHash(h *[]byte, data []byte) {
	if h == nil || *h == nil || len(data) == 0 {
		return
	}
	sum := sha512.Sum512(append(*h, data...))
	*h = sum[:]
}
