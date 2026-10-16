package handlers

import (
	"net/http"
	"strconv"
)

const maxTimes = 100

func Guarded(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.FormValue("n"))
	if err != nil || n < 0 || n > maxTimes {
		http.Error(w, "n out of range", http.StatusBadRequest)
		return
	}
	for i := 0; i < n; i++ {
		w.Write([]byte("x"))
	}
}
