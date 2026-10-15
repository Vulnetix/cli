package doppler

import (
	"regexp"
	"strings"
)

var personal = regexp.MustCompile(`^dp\.pt\.[A-Za-z0-9]{43}$`)

func IsPersonal(t string) bool { return strings.HasPrefix(t, "dp.pt.") && personal.MatchString(t) }
