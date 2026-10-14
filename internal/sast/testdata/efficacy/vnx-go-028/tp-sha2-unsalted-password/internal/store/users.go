package store

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
)

// One round of SHA-256 is billions of guesses per second on a GPU.
func hashPwd(pwd string) string {
~>	digest := sha256.Sum256([]byte(pwd))
	return base64.StdEncoding.EncodeToString(digest[:])
}

func (s *Store) ChangePassword(id, newPassword string) error {
~>	sum := sha512.Sum512(
		[]byte(newPassword),
	)
	return s.update(id, sum[:])
}

type Store struct{}

func (s *Store) update(string, []byte) error { return nil }
