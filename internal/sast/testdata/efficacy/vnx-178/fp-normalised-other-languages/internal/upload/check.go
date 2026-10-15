package upload

import (
	"mime/multipart"
	"path/filepath"
	"strings"
)

func blocked(h *multipart.FileHeader) bool {
	if strings.EqualFold(filepath.Ext(h.Filename), ".php") {
		return true
	}
	ext := strings.ToLower(filepath.Ext(h.Filename))
	return ext == ".exe"
}
