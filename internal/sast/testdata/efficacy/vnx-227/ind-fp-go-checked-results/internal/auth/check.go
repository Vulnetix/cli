package auth

import (
	"crypto/hmac"
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

var ErrDenied = errors.New("denied")

func Check(hash, password, got, want, tok, expTok []byte) error {
	if err := bcrypt.CompareHashAndPassword(
		hash,
		password,
	); err != nil {
		return ErrDenied
	}
	if !hmac.Equal(got, want) {
		return ErrDenied
	}
	ok := subtle.ConstantTimeCompare(tok, expTok) == 1
	if !ok {
		return ErrDenied
	}
	return nil
}
