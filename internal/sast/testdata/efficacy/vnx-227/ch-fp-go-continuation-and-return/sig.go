package sig

import "crypto/hmac"

func Valid(sig, expected []byte) bool {
	ok :=
		hmac.Equal(sig, expected)
	return ok
}

func Valid2(sig, expected []byte) bool {
	return hmac.Equal(sig, expected)
}
