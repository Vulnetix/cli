package store

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

var root = "/var/lib/app/tenants"

func CreateTenantDir(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.FormValue("tenant"))
	if err != nil {
		http.Error(w, "bad tenant", http.StatusBadRequest)
		return
	}
	if err := os.MkdirAll(filepath.Join(root, fmt.Sprint(id)), 0o750); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
