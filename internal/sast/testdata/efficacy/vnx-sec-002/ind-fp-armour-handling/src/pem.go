package pem

import "strings"

func Strip(s string) string {
	s = strings.ReplaceAll(s, "-----BEGIN PRIVATE KEY-----", "")
	return strings.TrimSpace(s)
}

func Wrap(b string) string {
	return "-----BEGIN PRIVATE KEY-----\n" + b + "\n-----END PRIVATE KEY-----\n"
}

func IsPEM(s string) bool { return strings.HasPrefix(s, "-----BEGIN PRIVATE KEY-----") }
