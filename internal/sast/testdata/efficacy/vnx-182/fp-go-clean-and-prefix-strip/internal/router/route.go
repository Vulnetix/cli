package router

import (
	"path/filepath"
	"strings"
)

func clean(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "/api/")
	return filepath.Clean("/" + p)
}

func version(v string) string {
	return strings.Replace(v, "v", "", 1)
}
