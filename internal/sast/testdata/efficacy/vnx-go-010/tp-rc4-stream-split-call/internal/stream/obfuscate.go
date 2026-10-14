package stream

import "crypto/rc4"

// Obfuscate "encrypts" the payload with RC4 and a per-tenant key.
func Obfuscate(tenantKey, payload []byte) ([]byte, error) {
~>	c, err := rc4.NewCipher(
		tenantKey,
	)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(payload))
	c.XORKeyStream(out, payload)
	return out, nil
}
