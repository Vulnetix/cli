package web

import (
	"io"
	"net/http"
)

func Fetch(w http.ResponseWriter, r *http.Request) {
~>	resp, err := http.Get(r.URL.Query().Get("url"))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
