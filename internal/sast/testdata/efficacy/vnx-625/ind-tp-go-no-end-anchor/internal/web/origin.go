package web

import "regexp"

~>var originRe = regexp.MustCompile(`^https://[a-z0-9-]+\.corp-internal\.net`)

func Allowed(o string) bool { return originRe.MatchString(o) }
