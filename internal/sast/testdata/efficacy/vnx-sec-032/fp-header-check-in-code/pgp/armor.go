package pgp

import "strings"

const privateHeader = "-----BEGIN PGP PRIVATE KEY BLOCK-----"

// IsPrivate reports whether an armored block holds a secret key.
func IsPrivate(armored string) bool {
	return strings.HasPrefix(strings.TrimSpace(armored), "-----BEGIN PGP PRIVATE KEY BLOCK-----")
}
