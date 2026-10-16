package api

import (
	"net/http"
	"strconv"
)

const maxBody = 1 << 20

func upload(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.Header.Get("Content-Length"))
	if n < 0 || n > maxBody {
		http.Error(w, "too large", 413)
		return
	}
	buf := make([]byte, n)
	r.Body.Read(buf)
}
