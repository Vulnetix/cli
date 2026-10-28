package lambdaext

import (
	"crypto/rand"
	"crypto/sha256"
)

// sha keys an event by its content and a random salt per sensor start, so a
// retried delivery of the same invocation is one event and two identical
// requests in different starts are two.
func sha(b []byte) []byte {
	sum := sha256.Sum256(append(b, startSalt[:]...))

	return sum[:16]
}

var startSalt = func() [16]byte {
	var s [16]byte
	_, _ = rand.Read(s[:])

	return s
}()
