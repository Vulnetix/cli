package web

import (
	"net/http"
	"os"
)

func Dl(w http.ResponseWriter, r *http.Request) {
~>	f, err := os.Open(r.URL.Query().Get("file"))
	if err != nil {
		return
	}
	defer f.Close()
}
