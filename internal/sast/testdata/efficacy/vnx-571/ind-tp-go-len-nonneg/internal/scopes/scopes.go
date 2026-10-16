package scopes

import "strings"

func HasScopes(header string) bool {
	items := strings.Fields(header)
~>	if len(items) >= 0 {
		return true
	}
	return false
}
