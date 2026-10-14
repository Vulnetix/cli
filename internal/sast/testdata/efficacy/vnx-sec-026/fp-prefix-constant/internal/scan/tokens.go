package scan

import "regexp"

const doPrefix = "dop_v1_"

var doToken = regexp.MustCompile(`dop_v1_[a-f0-9]{64}`)

// IsDOToken reports whether s looks like a dop_v1_ personal access token.
func IsDOToken(s string) bool { return doToken.MatchString(s) }
