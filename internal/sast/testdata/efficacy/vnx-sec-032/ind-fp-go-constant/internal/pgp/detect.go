package pgp

import "strings"

const privHeader = "-----BEGIN PGP PRIVATE KEY BLOCK-----"

func IsPrivate(s string) bool {
	return strings.HasPrefix(s, "-----BEGIN PGP PRIVATE KEY BLOCK-----")
}
