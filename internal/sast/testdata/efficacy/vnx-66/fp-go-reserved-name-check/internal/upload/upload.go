package upload

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var reserved = map[string]bool{"CON": true, "PRN": true, "AUX": true, "NUL": true, "COM1": true, "LPT1": true}

func Upload(w http.ResponseWriter, r *http.Request) {
	_, header, _ := r.FormFile("file")
	name := filepath.Base(header.Filename)
	stem := strings.ToUpper(strings.TrimSuffix(name, filepath.Ext(name)))
	if reserved[stem] {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	os.Create(filepath.Join("uploads", name))
}
