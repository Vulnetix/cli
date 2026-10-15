package cors

import "regexp"

~>var originRe = regexp.MustCompile(`^https://[a-z0-9-]+\.example\.com`)

func Allowed(origin string) bool {
	return originRe.MatchString(origin)
}

func Internal(host string) bool {
~>	ok, _ := regexp.MatchString(`^[a-z]+.corp.example.com$`, host)
	return ok
}
