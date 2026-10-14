package api

import (
	"errors"
	"math"
	"net/http"
	"strconv"
)

var errRange = errors.New("out of range")

func ParsePage(r *http.Request) (int32, uint16, uint64, error) {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		return 0, 0, 0, err
	}
	if n < 1 || n > math.MaxInt32 {
		return 0, 0, 0, errRange
	}
	p, err := strconv.Atoi(r.URL.Query().Get("port"))
	if err != nil || p <= 0 || p > 65535 {
		return 0, 0, 0, errRange
	}
	off, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	if err != nil || off < 0 {
		return 0, 0, 0, errRange
	}
	return int32(n), uint16(p), uint64(off), nil
}

func Level(s string) int8 {
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	v = clamp(v, -10, 10)
	return int8(v)
}

func clamp(v, lo, hi int) int { return max(lo, min(v, hi)) }
