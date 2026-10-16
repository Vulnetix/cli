package api

import (
	"net/http"
	"os"
	"path/filepath"
)

func Delete(w http.ResponseWriter, r *http.Request) {
	victim := filepath.Join("/var/app/tmp", r.FormValue("target"))
~>	if err := os.Remove(victim); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
