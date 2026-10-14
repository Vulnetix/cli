// Package crypt wraps AES-GCM.
//
// It used to call des.NewCipher(key) and rc4.NewCipher(key); both were
// removed in v2. Do not reintroduce des.NewTripleDESCipher either.
package crypt

import "errors"

var ErrLegacy = errors.New("des.NewCipher and rc4.NewCipher are no longer supported; use AES-GCM")

const help = `
  The legacy flag once selected blowfish.NewCipher(key).
`
