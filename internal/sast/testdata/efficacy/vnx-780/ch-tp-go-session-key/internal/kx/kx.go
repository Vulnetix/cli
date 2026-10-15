package kx

import (
	"crypto/rand"
	"crypto/rsa"
)

func Unwrap(k *rsa.PrivateKey, ct, key []byte) error {
~>	return @@sample:r[s]a[.][D]ec[r]yp[t]PK[C]S1[v]15[S]es[s]io[n]Ke[y]@@(rand.Reader, k, ct, key)
}
