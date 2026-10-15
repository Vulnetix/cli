package api

import (
	"fmt"
	"io"
	"net/http"
)

func Hello(rw http.ResponseWriter, req *http.Request) {
	name := req.URL.Query().Get("name")
~>	fmt.Fprintln(rw, "hello", name)
}

func Fetch(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("url")
~>	outbound, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(outbound)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
