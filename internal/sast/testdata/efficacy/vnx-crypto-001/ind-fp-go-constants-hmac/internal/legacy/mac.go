package legacy

import (
	"crypto/hmac"
	"crypto/md5"
)

// DigestLen is the length of the digests the old protocol carried.
const DigestLen = md5.Size

// Sign computes the HMAC-MD5 the v1 protocol requires.
func Sign(key, msg []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
