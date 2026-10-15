package auth

import (
	"encoding/base64"
	"encoding/hex"
)

func encodeRecord(passwordHash, passwordSalt []byte) (string, string) {
	h := @@sample:b[a]se[6]4[.][S]td[E]nc[o]di[n]g[.][E]nc[o]de[T]oS[t]ri[n]g@@(passwordHash)
	s := hex.EncodeToString(passwordSalt)
	return h, s
}
