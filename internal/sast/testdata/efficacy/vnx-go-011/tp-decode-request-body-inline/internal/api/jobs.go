package api

import (
	"encoding/gob"
	"net/http"
)

type Job struct {
	Name string
	Args []string
}

func SubmitJob(w http.ResponseWriter, r *http.Request) {
	var job Job
~>	if err := gob.NewDecoder(r.Body).Decode(&job); err != nil {
		http.Error(w, "bad job", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) Import(rw http.ResponseWriter, in *http.Request) {
	var batch []Job
~>	gob.NewDecoder(in.Body).Decode(&batch)
}
