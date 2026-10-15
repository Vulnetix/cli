package hook

import "crypto/subtle"

func OK(sig, expected []byte) bool {
	if len(sig) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(sig, expected) == 1
}
