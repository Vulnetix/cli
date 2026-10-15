package svc

import (
	"net/http"
	"strconv"
)

func Handle(w http.ResponseWriter, r *http.Request) {
~>	id, err := strconv.ParseUint(r.URL.Query().Get("id"), 0, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	_ = id
}
