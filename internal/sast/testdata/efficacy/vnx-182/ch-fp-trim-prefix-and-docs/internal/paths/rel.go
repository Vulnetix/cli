package paths

import (
	"path/filepath"
	"strings"
)

func Rel(p string) string {
	p = strings.TrimPrefix(p, "./")
	return filepath.Clean("/" + p)
}

func Ellipsis(s string) string {
	return strings.ReplaceAll(s, "...", "")
}
