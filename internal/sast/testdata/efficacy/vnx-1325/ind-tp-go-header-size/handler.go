package api

import (
	"net/http"
	"strconv"
)

func upload(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.Header.Get("Content-Length"))
	if err != nil {
		http.Error(w, "bad", 400)
		return
	}
~>	buf := make([]byte, n)
	r.Body.Read(buf)
}
