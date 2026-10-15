package api

import (
	"net/http"
	"strconv"
)

func Average(w http.ResponseWriter, r *http.Request) {
	sum := 1000
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
~>	sum /= count
	w.Write([]byte(strconv.Itoa(sum)))
}
