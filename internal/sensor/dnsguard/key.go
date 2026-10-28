package dnsguard

import (
	"crypto/rand"
	"encoding/hex"
)

func newKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:])

	return hex.EncodeToString(b[:])
}
