package handlers

import (
	"net/http"
	"strings"
)

func Transfer(w http.ResponseWriter, r *http.Request) {
~>	if !strings.Contains(r.Referer(), "bank.example.com") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
