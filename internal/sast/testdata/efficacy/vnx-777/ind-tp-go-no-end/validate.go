package validate

import "regexp"

func ValidID(id string) bool {
~>	ok, _ := regexp.MatchString(`^[A-Za-z0-9]{8,32}`, id)
	return ok
}
