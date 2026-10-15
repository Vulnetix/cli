package api

import (
	"io"
	"net/http"
	"os"
)

func Read(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("p")
	f, err := os.OpenFile(p, os.O_RDONLY, 0)
	if err != nil {
		return
	}
	defer f.Close()
	io.Copy(w, f)
}
