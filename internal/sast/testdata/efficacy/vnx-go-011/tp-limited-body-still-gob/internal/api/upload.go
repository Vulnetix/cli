package api

import (
	"encoding/gob"
	"net/http"
)

// A size cap bounds the input, but gob's decoder is not hardened against
// adversarial streams (nesting and type descriptors still cost the server).
func Upload(w http.ResponseWriter, r *http.Request) {
	limited := http.MaxBytesReader(w, r.Body, 1<<20)
	var m map[string]string
~>	if err := gob.NewDecoder(limited).Decode(&m); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}
