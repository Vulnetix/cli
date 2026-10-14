package api

import (
	"encoding/gob"
	"encoding/json"
	"net/http"
)

type Job struct {
	Name string `json:"name"`
}

// The request is JSON into an explicit struct; gob only encodes the reply
// for the internal worker that asked for it.
func SubmitJob(w http.ResponseWriter, r *http.Request) {
	var job Job
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&job); err != nil {
		http.Error(w, "bad job", http.StatusBadRequest)
		return
	}
	gob.NewEncoder(w).Encode(job)
}
