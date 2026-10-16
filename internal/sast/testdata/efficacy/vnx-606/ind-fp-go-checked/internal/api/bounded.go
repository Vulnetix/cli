package api

import (
	"net/http"
	"strconv"
)

const maxRetries = 5

func (s *Server) BoundedRetry(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.URL.Query().Get("retries"))
	if err != nil {
		http.Error(w, "bad retries", http.StatusBadRequest)
		return
	}
	if n > maxRetries {
		n = maxRetries
	}
	for i := 0; i < n; i++ {
		if s.upstream.Ping() == nil {
			return
		}
	}
}

func (s *Server) Clamped(w http.ResponseWriter, r *http.Request) {
	size, _ := strconv.Atoi(r.FormValue("size"))
	size = min(size, 100)
	for i := 0; i < size; i++ {
		s.emit(w, i)
	}
}

func (s *Server) Guarded(w http.ResponseWriter, r *http.Request) {
	count, _ := strconv.Atoi(r.Header.Get("X-Count"))
	for i := 0; i < count && i < maxRetries; i++ {
		s.emit(w, i)
	}

	for i := range s.items {
		s.emit(w, i)
	}
	for i := 0; i < len(s.items); i++ {
		s.emit(w, i)
	}
	for i := 0; i < 10; i++ {
		s.emit(w, i)
	}
}
