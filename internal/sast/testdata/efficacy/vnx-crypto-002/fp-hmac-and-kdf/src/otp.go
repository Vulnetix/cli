package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
)

func HOTP(key []byte, counter uint64) []byte {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	return m.Sum(nil)
}

const digestSize = sha1.Size
