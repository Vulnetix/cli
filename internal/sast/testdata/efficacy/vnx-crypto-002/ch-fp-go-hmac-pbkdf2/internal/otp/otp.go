package otp

import (
	"crypto/hmac"
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
)

func HOTP(key, counter []byte) []byte {
	m := hmac.New(sha1.New, key)
	m.Write(counter)
	return m.Sum(nil)
}

func Legacy(pw, salt []byte) []byte {
	return pbkdf2.Key(pw, salt, 600000, 32, sha1.New)
}
