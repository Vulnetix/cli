package sig

import (
	weak "crypto/md5"
	"encoding/hex"
)

func Sign(secret, body string) string {
~>	sum := weak.Sum([]byte(secret + body))
	return hex.EncodeToString(sum[:])
}

func Stream() []byte {
~>	h := weak.New()
	h.Write([]byte("x"))
	return h.Sum(nil)
}
