package app

import (
	"crypto/rand"
	"encoding/base64"
)

func NewPasswordResetToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return @@sample:b[a]se[6]4[.][R]aw[U]RL[E]nc[o]di[n]g[.][E]nc[o]de[T]oS[t]ri[n]g@@(b)
}
