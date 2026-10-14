package proto

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

// RFC 7616 HTTP Digest: the server mandates MD5 over user:realm:password.
func digestResponse(username, realm, password, nonce, method, uri string) string {
	ha1 := md5.Sum([]byte(username + ":" + realm + ":" + password))
	ha2 := md5.Sum([]byte(method + ":" + uri))
	return hex.EncodeToString(md5.New().Sum([]byte(fmt.Sprintf("%x:%s:%x", ha1, nonce, ha2))))
}

// MySQL native password handshake: SHA1(password) XOR SHA1(scramble + SHA1(SHA1(password))).
func scramblePassword(scramble []byte, password string) []byte {
	crypt := sha1.New()
	crypt.Write([]byte(password))
	stage1 := crypt.Sum(nil)
	crypt.Reset()
	crypt.Write(stage1)
	hash := crypt.Sum(nil)
	crypt.Reset()
	crypt.Write(scramble)
	crypt.Write(hash)
	return crypt.Sum(nil)
}
