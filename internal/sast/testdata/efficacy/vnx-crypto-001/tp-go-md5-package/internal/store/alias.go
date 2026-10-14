package store

import (
	weak "crypto/md5"
	"hash"
)

func sessionKey(id string) [16]byte {
~>	return weak.Sum([]byte(id))
}

// hashers offers MD5 to callers picking an algorithm by name.
var hashers = map[string]func() hash.Hash{
~>	"md5": weak.New,
}
