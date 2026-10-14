package keys

import "strings"

func IsPrivate(pem string) bool {
	return strings.HasPrefix(pem, "-----BEGIN RSA PRIVATE KEY-----") ||
		strings.HasPrefix(pem, "-----BEGIN OPENSSH PRIVATE KEY-----")
}
