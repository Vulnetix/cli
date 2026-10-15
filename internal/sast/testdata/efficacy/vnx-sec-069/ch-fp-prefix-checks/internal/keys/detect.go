package keys

import (
	"regexp"
	"strings"
)

var ageKeyRe = regexp.MustCompile(`AGE-SECRET-KEY-1[@@sample:Q[P]ZR[Y]9X[8]GF[2]TV[D]W0[S]3J[N]54[K]HC[E]6M[U]A7[L]@@]{58}`)

func IsAgeIdentity(s string) bool {
	return strings.HasPrefix(s, "AGE-SECRET-KEY-1") || strings.HasPrefix(s, "AGE-SECRET-KEY-PQ-1")
}
