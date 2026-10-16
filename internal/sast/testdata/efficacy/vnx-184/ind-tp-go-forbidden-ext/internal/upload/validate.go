package upload

import (
	"errors"
	"path/filepath"
)

~>var forbiddenExtensions = []string{".php", ".exe", ".sh"}

func Validate(name string) error {
	ext := filepath.Ext(name)
	for _, bad := range forbiddenExtensions {
		if ext == bad {
			return errors.New("file type not allowed")
		}
	}
	return nil
}
