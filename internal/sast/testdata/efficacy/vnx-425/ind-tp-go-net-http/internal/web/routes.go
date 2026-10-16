package web

import (
	"encoding/json"
	"net/http"
)

func Register(mux *http.ServeMux) {
~>	mux.HandleFunc("/admin/flags", toggleFlags)
	mux.HandleFunc("/healthz", healthz)
}

func toggleFlags(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	flags.Toggle(name)
	json.NewEncoder(w).Encode(flags.All())
}

func healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
