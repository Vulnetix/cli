package auth

import "regexp"

func AllowedRedirect(u string) bool {
~>	ok, _ := regexp.MatchString(`^https://login\.example\.com`, u)
	return ok
}

func AllowedCallback(u string) bool {
~>	ok, _ := regexp.MatchString("^https://(www.)?example.dev/", u)
	return ok
}
