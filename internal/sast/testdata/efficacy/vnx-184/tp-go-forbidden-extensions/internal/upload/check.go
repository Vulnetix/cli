package upload

import (
	"path/filepath"
	"strings"
)

~>var forbiddenExtensions = []string{".php", ".exe", ".sh"}

func Allowed(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	for _, bad := range forbiddenExtensions {
		if ext == bad {
			return false
		}
	}
	return true
}
