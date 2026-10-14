package api

import (
	"encoding/json"
	"net/http"
)

type Event struct{ Kind string }

// We used to call gob.NewDecoder(r.Body) here; JSON is safer for untrusted input.
func Events(w http.ResponseWriter, r *http.Request) {
	var ev Event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, "never use gob.NewDecoder(r.Body) on requests", http.StatusBadRequest)
		return
	}
}
