package store

// Do not write keys like aes.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
// here; load them from KMS through LoadKey instead.
func LoadKey() []byte { return nil }
