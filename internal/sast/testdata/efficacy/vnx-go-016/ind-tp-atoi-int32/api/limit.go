package api

import (
	"net/http"
	"strconv"
)

func List(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		http.Error(w, "bad limit", 400)
		return
	}
	q := Query{
~>		Limit: int32(n),
	}
	run(q)
}
