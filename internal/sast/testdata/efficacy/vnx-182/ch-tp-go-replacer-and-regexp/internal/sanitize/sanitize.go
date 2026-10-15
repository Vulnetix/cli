package sanitize

import (
	"regexp"
	"strings"
)

~>var pathCleaner = strings.NewReplacer("../", "", "..\\", "")

func Path(p string) string {
	return pathCleaner.Replace(p)
}

func HTML(s string) string {
~>	return regexp.MustCompile(`(?i)<script>`).ReplaceAllString(s, "")
}
