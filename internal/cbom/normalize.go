package cbom

import (
	"strings"

	"github.com/vulnetix/cli/v3/internal/sast"
)

// Normalize folds a cryptographic-algorithm token to a canonical comparison key:
// lower-cased with every non-alphanumeric character (spaces, '-', '_', '.', '/')
// removed. This is what makes "SHA256", "Sha256", "sha256" and "SHA_256" all
// resolve to the same algorithm and be stored under one canonical SPDX name.
//
//	Normalize("SHA-256")  == "sha256"
//	Normalize("Sha_256")  == "sha256"
//	Normalize("ML-KEM-768") == "mlkem768"
func Normalize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+':
			// keep '+' so NTRU+ and SPHINCS+ remain distinguishable
			b.WriteRune(r)
		default:
			// drop separators
		}
	}
	return b.String()
}

// canonicalLang collapses a catalog/source language label to the canonical form
// used by the file walker (e.g. "node"/"ts" -> "javascript").
func canonicalLang(label string) string {
	return sast.CanonicalLanguage(label)
}
