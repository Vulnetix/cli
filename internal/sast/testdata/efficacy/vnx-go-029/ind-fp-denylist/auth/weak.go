package auth

var commonPasswords = map[string]bool{
	"admin":    true,
	"password": true,
	"123456":   true,
	"changeme": true,
}

func IsWeak(candidate string) bool {
	return commonPasswords[candidate]
}
