package scan

import "regexp"

var doToken = regexp.MustCompile(`\bdop_v1_[a-f0-9]{64}\b`)
