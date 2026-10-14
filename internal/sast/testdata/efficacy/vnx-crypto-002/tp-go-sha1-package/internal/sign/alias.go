package sign

import (
	"hash"

	oldsha "crypto/sha1"
)

func cacheBuster(b []byte) [20]byte {
~>	return oldsha.Sum(b)
}

var algorithms = map[string]func() hash.Hash{
~>	"sha1": oldsha.New,
}
