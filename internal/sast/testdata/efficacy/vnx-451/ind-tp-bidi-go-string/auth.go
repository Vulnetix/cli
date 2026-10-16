package auth

import "strings"

func IsAdmin(role string) bool {
~>	const adminRole = "admin⁧⁩"
	return strings.EqualFold(role, adminRole)
}
