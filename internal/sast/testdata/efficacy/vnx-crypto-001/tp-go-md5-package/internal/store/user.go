package store

import (
	"crypto/md5"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// Md5Sum hashes a password for storage.
func Md5Sum(text string) string {
~>	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func otpDigest(otp string) string {
~>	return fmt.Sprintf("%x", md5.Sum([]byte(otp)))
}

func fileDigest(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
~>	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

var certTemplate = x509.Certificate{
~>	SignatureAlgorithm: x509.MD5WithRSA,
}
