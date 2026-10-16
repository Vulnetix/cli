package api

import (
	"encoding/gob"
	"net/http"
)

type Job struct {
	Name string
	Args map[string]any
}

func Submit(w http.ResponseWriter, r *http.Request) {
	var j Job
~>	if err := gob.NewDecoder(r.Body).Decode(&j); err != nil {
		http.Error(w, "bad", 400)
		return
	}
	enqueue(j)
}
