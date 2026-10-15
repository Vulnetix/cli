package api

import (
	"net/http"
	"strconv"
)

func Repeat(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("times")
	times, err := strconv.Atoi(raw)
	if err != nil {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
~>	for i := 0; i < times; i++ {
		w.Write([]byte("hello\n"))
	}
}

func Depth(w http.ResponseWriter, r *http.Request) {
	d, _ := strconv.ParseInt(r.FormValue("depth"), 10, 64)
~>	for level := int64(0); level < d; level++ {
		w.Write([]byte("."))
	}
}
