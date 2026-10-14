package pwhash

import (
	"golang.org/x/crypto/blowfish"
)

// expensiveBlowfishSetup is the bcrypt (EksBlowfish) key schedule: the
// salted cipher is a password-hashing primitive, not data encryption.
func expensiveBlowfishSetup(key []byte, cost uint32, salt []byte) (*blowfish.Cipher, error) {
	c, err := blowfish.NewSaltedCipher(key, salt)
	if err != nil {
		return nil, err
	}
	rounds := uint64(1) << cost
	for i := uint64(0); i < rounds; i++ {
		blowfish.ExpandKey(key, c)
		blowfish.ExpandKey(salt, c)
	}
	return c, nil
}
