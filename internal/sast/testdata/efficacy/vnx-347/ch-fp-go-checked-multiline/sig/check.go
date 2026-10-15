package sig

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
)

func Check(pub ed25519.PublicKey, msg, s, token, want []byte) error {
	valid := ed25519.Verify(
		pub,
		msg,
		s,
	)
	if !valid {
		return errors.New("bad signature")
	}
	if subtle.ConstantTimeCompare(token, want) != 1 {
		return errors.New("bad token")
	}
	return nil
}
