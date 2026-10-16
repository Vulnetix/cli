package links

import "regexp"

var docsLink = regexp.MustCompile(`^https://docs\.acme\.io/`)
var semver = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

func IsDocsLink(u string) bool {
	return docsLink.MatchString(u)
}
