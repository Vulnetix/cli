package handlers

import (
	"fmt"
	"net/http"
	"strconv"
)

func Repeat(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("times")
	times, err := strconv.Atoi(raw)
	if err != nil {
		http.Error(w, "bad times", http.StatusBadRequest)
		return
	}
~>	for i := 0; i < times; i++ {
		fmt.Fprintln(w, "hello")
	}
}
