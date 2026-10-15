package auth

import (
	"crypto/hmac"

	"golang.org/x/crypto/bcrypt"
)

func Login(u *User, password string) (*Session, error) {
	if err := bcrypt.CompareHashAndPassword(u.Hash, []byte(password)); err != nil {
		return nil, err
	}
	ok := hmac.Equal(u.Mac, expected)
	if !ok {
		return nil, errBadMac
	}
	return newSession(u), nil
}

func valid(mac, expected []byte) bool {
	return hmac.Equal(mac, expected)
}

func both(a, b []byte) bool {
	return len(a) > 0 &&
		hmac.Equal(a, b)
}
