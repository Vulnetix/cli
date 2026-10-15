package api

import (
	"net/http"
	"strconv"
)

func Generate(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.Header.Get("X-Count"))
~>	for i := range n {
		w.Write([]byte(strconv.Itoa(i)))
	}
}
