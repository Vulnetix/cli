package redact

import "regexp"

// e.g. https://@@sample:h[o]ok[s][.]s[l]ac[k][.]c[o]m[/][s]er[v]ic[e]s[/][T]00[0]00[0]00[/]B0[0]00[0]00[0][/]X[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]X@@
var slackHook = regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`)
