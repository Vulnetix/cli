package scan

import "regexp"

var doToken = regexp.MustCompile(`dop_v1_[0-9a-f]{64}`)

const doPrefix = "dop_v1_"
