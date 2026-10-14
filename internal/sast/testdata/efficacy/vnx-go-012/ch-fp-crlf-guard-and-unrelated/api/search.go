package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

func Search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(lookup(q))
}

func Echo(w http.ResponseWriter, r *http.Request) {
	tag := r.FormValue("tag")
	if strings.ContainsAny(tag, "\r\n") {
		http.Error(w, "invalid tag", http.StatusBadRequest)
		return
	}
	w.Header().Set("X-Tag", tag)
}

func lookup(string) []string { return nil }
