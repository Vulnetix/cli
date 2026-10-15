package box

import (
	"crypto/rand"
	"crypto/rsa"
)

func Seal(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
~>	return rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
}

func Open(priv *rsa.PrivateKey, ct []byte) ([]byte, error) {
~>	out, err := rsa.DecryptPKCS1v15(nil, priv, ct)
	return out, err
}

func OpenKey(priv *rsa.PrivateKey, ct, key []byte) error {
~>	return @@sample:r[s]a[.][D]ec[r]yp[t]PK[C]S1[v]15[S]es[s]io[n]Ke[y]@@(rand.Reader, priv, ct, key)
}
