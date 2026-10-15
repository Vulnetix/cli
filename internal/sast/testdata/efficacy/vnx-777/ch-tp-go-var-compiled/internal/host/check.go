package host

import "regexp"

var hostRe = regexp.MustCompile(`^[a-z0-9.-]+`)

func Allowed(h string) bool {
~>	return hostRe.MatchString(h)
}
