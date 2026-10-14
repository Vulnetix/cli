package rpc

import (
	"encoding/gob"
	"net/http"
)

type Command struct {
	Op   string
	Args []string
}

type Server struct{ queue chan Command }

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var cmd Command
~>	dec := gob.NewDecoder(req.Body)
	if err := dec.Decode(&cmd); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	s.queue <- cmd
	w.WriteHeader(http.StatusAccepted)
}
