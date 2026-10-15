package api

import (
	"io"
	"net/http"
)

func upload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	buf := make([]byte, 32*1024)
	seen := make(map[string]int)
	limited := io.LimitReader(r.Body, 10<<20)
	n, _ := io.CopyBuffer(io.Discard, limited, buf)
	seen[name] = int(n)
}
