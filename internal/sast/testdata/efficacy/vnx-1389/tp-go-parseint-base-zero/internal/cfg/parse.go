package cfg

import (
	"net/http"
	"strconv"
)

func Mask(r *http.Request) (int64, error) {
	v := r.URL.Query().Get("mask")
~>	return strconv.ParseInt(v, 0, 64)
}

func Perm(s string) (uint32, error) {
~>	n, err := strconv.ParseUint(s, 0, 32)
	return uint32(n), err
}
