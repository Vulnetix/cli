package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

func PasswordDigest(pw, salt string) string {
~>	h := sha1.New()
	h.Write([]byte(salt + pw))
	return hex.EncodeToString(h.Sum(nil))
}

func Fingerprint(cert []byte) string {
~>	return fmt.Sprintf("%x", sha1.Sum(cert))
}

func SignBlob(key *rsa.PrivateKey, blob []byte) ([]byte, error) {
~>	sum := sha1.Sum(blob)
~>	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum[:])
}

var template = x509.Certificate{
~>	SignatureAlgorithm: x509.SHA1WithRSA,
}

var ecTemplate = x509.Certificate{
~>	SignatureAlgorithm: x509.ECDSAWithSHA1,
}
