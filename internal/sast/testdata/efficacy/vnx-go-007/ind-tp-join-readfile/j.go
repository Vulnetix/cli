package web

import (
	"net/http"
	"os"
	"path/filepath"
)

func Doc(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	p := filepath.Join("/srv/docs", name)
~>	data, _ := os.ReadFile(p)
	w.Write(data)
}
