package mac

import (
	"crypto/hmac"
	"crypto/md5"
)

// Sign computes HMAC-MD5, which a legacy partner API still requires.
func Sign(key, msg []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

const digestLen = md5.Size
