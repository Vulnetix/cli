package upload

import (
	"mime/multipart"
	"path/filepath"
	"strings"
)

func Blocked(h *multipart.FileHeader) bool {
	return strings.EqualFold(filepath.Ext(h.Filename), ".exe")
}
