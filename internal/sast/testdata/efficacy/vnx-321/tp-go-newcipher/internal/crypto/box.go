package crypto

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
)

~>var signingKey = []byte("@@sample:f[1]e2[d]3c[4]b5[a]69[7]88[f]1e[2]d3[c]4@@")

func block() {
~>	b, _ := aes.NewCipher([]byte("@@sample:0[1]23[4]56[7]89[a]bc[d]ef[0]12[3]45[6]78[9]ab[c]de[f]@@"))
~>	m := hmac.New(sha256.New, []byte("static-mac-key"))
	_, _ = b, m
}
