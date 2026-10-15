package legacy

import (
	"crypto/hmac"
	"crypto/md5"
)

func Mac(key, msg []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
