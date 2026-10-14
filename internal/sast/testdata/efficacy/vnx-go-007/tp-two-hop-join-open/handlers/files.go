package handlers

import (
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/mux"
)

const baseDir = "/srv/files"

func GetFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	full := filepath.Join(baseDir, vars["name"])
~>	f, err := os.Open(full)
	if err != nil {
		return
	}
	defer f.Close()
	io.Copy(w, f)
}

func ListDir(w http.ResponseWriter, r *http.Request) {
	sub := r.PathValue("dir")
	target := filepath.Clean(filepath.Join(baseDir, sub))
~>	entries, err := os.ReadDir(target)
	if err != nil {
		return
	}
	for _, e := range entries {
		io.WriteString(w, e.Name()+"\n")
	}
}
