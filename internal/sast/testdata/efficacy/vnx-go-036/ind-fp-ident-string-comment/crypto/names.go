package crypto

import "errors"

type ECBMode struct{}

var ErrECBNotSupported = errors.New("ECB mode is not supported; use GCM")

// NewECBEncrypter is deliberately absent from the standard library.
func describe() string { return "we never call ecb.NewECBEncrypter(block)" }
