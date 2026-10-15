package api

import (
	"net/http"
	"strconv"
)

const maxLimit = 500

func clampLimit(n int) int {
	if n < 1 {
		return 1
	}
	if n > maxLimit {
		return maxLimit
	}
	return n
}

func List(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	limit = clampLimit(limit)
	for i := 0; i < limit; i++ {
		w.Write([]byte(strconv.Itoa(i)))
	}
}
