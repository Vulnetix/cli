package server

import (
	"net/http"
	"strconv"
)

const maxChunk = 1 << 20

func chunk(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.FormValue("n"))
	if err != nil || n <= 0 || n > maxChunk {
		http.Error(w, "bad size", http.StatusBadRequest)
		return
	}
	buf := make([]byte, n)
	_, _ = r.Body.Read(buf)
}
