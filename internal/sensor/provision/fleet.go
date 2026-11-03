package provision

import (
	"fmt"
	"regexp"
	"strings"
)

// fleetName is what the site accepts: it becomes a repository name, so it has
// no path or whitespace characters.
var fleetName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// NormalizeFleet lowercases and checks a fleet name. "" is no fleet.
func NormalizeFleet(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", nil
	}
	if !fleetName.MatchString(s) {
		return "", fmt.Errorf("%q is not a fleet name: use 1 to 63 characters of a-z, 0-9, dot, dash or underscore, starting with a letter or digit", s)
	}

	return s, nil
}
