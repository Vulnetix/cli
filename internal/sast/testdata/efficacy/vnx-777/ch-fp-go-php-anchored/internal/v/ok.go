package v

import "regexp"

var portRe = regexp.MustCompile(`^[0-9]{1,5}$`)

func ValidPort(p string) bool {
	ok, _ := regexp.MatchString(`^[a-z]+$`, p)
	return ok && portRe.MatchString(p)
}
