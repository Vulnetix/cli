package scan

import "regexp"

var githubToken = regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b`)
var gitlabToken = regexp.MustCompile(`glpat-[0-9A-Za-z_\-]{20}`)
