package store

import (
	"crypto/sha1"
	"crypto/sha512"
	"fmt"
)

type Profile struct {
	Passphrase string
	Salt       string
}

func (p *Profile) Digest() string {
~>	hashed := sha512.Sum512([]byte(p.Passphrase))
	return fmt.Sprintf("%x", hashed)
}

func legacyHash(salt, pwd string) string {
~>	return fmt.Sprintf("%x", sha1.Sum([]byte(salt+pwd)))
}
