package api

import (
	"math"
	"net/http"
	"strconv"
)

func pageSize(r *http.Request) (int32, error) {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		return 0, err
	}
	if n < 1 || n > math.MaxInt32 {
		return 0, errBadLimit
	}
	return int32(n), nil
}
