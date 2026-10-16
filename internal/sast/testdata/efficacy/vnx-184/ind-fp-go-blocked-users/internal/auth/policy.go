package auth

var blockedUsers = []string{"root", "admin", "nobody"}

func CanLogin(user string) bool {
	for _, u := range blockedUsers {
		if u == user {
			return false
		}
	}
	return true
}
