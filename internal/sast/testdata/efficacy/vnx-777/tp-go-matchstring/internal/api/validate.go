package api

import (
	"errors"
	"regexp"
)

var tenantRe = regexp.MustCompile(`^[a-z0-9-]+`)

func validateTenant(t string) error {
~>	if !tenantRe.MatchString(t) {
		return errors.New("invalid tenant")
	}
	return nil
}

func validatePort(p string) bool {
~>	ok, _ := regexp.MatchString("[0-9]{1,5}$", p)
	return ok
}

func validateRef(r string) bool {
~>	return regexp.MustCompile(`^[A-Za-z0-9_.]{1,64}`).MatchString(r)
}
