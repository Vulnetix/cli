package upload

import (
	"net/http"
	"path/filepath"
	"strings"
)

var allowed = map[string]bool{".png": true, ".jpg": true, ".gif": true}

func Accept(r *http.Request) bool {
	_, header, err := r.FormFile("image")
	if err != nil {
		return false
	}
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext == ".php" || ext == ".svg" {
		return false
	}
	if strings.EqualFold(filepath.Ext(header.Filename), ".exe") {
		return false
	}
	return allowed[ext]
}
