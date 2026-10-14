package auth

import (
	"crypto"
	_ "crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"io"
)

func StoreCredential(user, passwd string) string {
	h := sha1.New()
~>	h.Write([]byte(user + ":" + passwd))
	return hex.EncodeToString(h.Sum(nil))
}

func Verify(stored, pwd string) bool {
	hasher := crypto.MD5.New()
~>	io.WriteString(hasher, pwd)
	return hex.EncodeToString(hasher.Sum(nil)) == stored
}
