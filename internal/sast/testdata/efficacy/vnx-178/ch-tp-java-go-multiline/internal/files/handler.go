package files

import (
	"net/http"
	"path/filepath"
	"strings"
)

func Upload(w http.ResponseWriter, r *http.Request) {
	_, header, err := r.FormFile("file")
	if err != nil {
		return
	}
~>	if strings.HasSuffix(header.Filename, ".exe") {
		http.Error(w, "blocked", http.StatusBadRequest)
		return
	}
	save(filepath.Base(header.Filename))
}
