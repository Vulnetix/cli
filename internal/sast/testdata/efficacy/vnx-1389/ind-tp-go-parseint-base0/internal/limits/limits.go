package limits

import (
	"net/http"
	"strconv"
)

func Parse(r *http.Request) (int64, error) {
	s := r.URL.Query().Get("limit")
~>	n, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return 0, err
	}
	return n, nil
}
