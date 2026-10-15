package api

import (
	"net/http"
	"strconv"
)

const maxTimes = 50

func Repeat(w http.ResponseWriter, r *http.Request) {
	times, err := strconv.Atoi(r.URL.Query().Get("times"))
	if err != nil || times > maxTimes {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	for i := 0; i < times; i++ {
		w.Write([]byte("hello\n"))
	}
	n, _ := strconv.Atoi(r.FormValue("n"))
	n = min(n, maxTimes)
	for i := 0; i < n; i++ {
		w.Write([]byte("."))
	}
}
