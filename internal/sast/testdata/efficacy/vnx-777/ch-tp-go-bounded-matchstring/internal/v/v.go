package v

import "regexp"

func ValidPort(p string) bool {
~>	ok, _ := regexp.MatchString(`[0-9]{1,5}`, p)
	return ok
}
