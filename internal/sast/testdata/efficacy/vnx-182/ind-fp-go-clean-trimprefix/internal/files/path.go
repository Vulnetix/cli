package files

import (
	"errors"
	"path/filepath"
	"strings"
)

func Resolve(base, raw string) (string, error) {
	rel := strings.TrimPrefix(raw, "/static/")
	full := filepath.Join(base, filepath.Clean("/"+rel))
	if !strings.HasPrefix(full, base+string(filepath.Separator)) {
		return "", errors.New("outside base")
	}
	return full, nil
}
