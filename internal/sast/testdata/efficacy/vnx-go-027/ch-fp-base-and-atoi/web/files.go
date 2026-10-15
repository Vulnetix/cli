package web

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

func Avatar(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("file"))
	data, err := os.ReadFile(filepath.Join("/srv/avatars", name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write(data)
}

func Invoice(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	http.ServeFile(w, r, fmt.Sprintf("/srv/invoices/%d.pdf", id))
}
