package srv

import (
	"net/http"
	"strconv"
)

func portFrom(r *http.Request) (uint16, error) {
	n, err := strconv.ParseInt(r.URL.Query().Get("port"), 10, 64)
	if err != nil {
		return 0, err
	}
~>	port := uint16(n)
	return port, nil
}
