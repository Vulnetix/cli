package api

import (
	"encoding/json"
	"net/http"
)

func Submit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var j Job
	if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
		http.Error(w, "bad", 400)
	}
}
