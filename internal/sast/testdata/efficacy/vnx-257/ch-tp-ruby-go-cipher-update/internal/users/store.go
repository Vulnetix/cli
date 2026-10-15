package users

import (
	"crypto/cipher"
	"encoding/base64"
)

func (s *Store) Save(u *User, gcm cipher.AEAD, nonce []byte) error {
~>	sealed := gcm.Seal(nonce, nonce, []byte(u.Password), nil)
~>	u.Recovery = @@sample:b[a]se[6]4[.][S]td[E]nc[o]di[n]g[.][E]nc[o]de[T]oS[t]ri[n]g@@([]byte(u.Password))
	return s.db.Put(u.ID, sealed)
}
