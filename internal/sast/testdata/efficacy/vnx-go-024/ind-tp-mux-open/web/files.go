package web

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/mux"
)

func File(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
~>	f, err := os.Open(filepath.Join("/srv/files", name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
}
