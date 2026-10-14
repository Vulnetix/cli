package auth

import "net/http"

// Never call jwt.NewParser().ParseUnverified(raw, claims) in a handler, and
// never return jwt.UnsafeAllowNoneSignatureType from a key function.
/*
	tok, _ := jwt.Parse(raw, keyFunc)
	tok.UnsafeClaimsWithoutVerification(&c)
*/
const lintHint = "jwt.UnsafeAllowNoneSignatureType is forbidden; so is jwt.WithVerify(false)"

func Explain(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(lintHint))
}
