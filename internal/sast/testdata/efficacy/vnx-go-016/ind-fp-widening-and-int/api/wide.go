package api

import (
	"strconv"
	"time"
)

func Timeout(s string) time.Duration {
	n, _ := strconv.Atoi(s)
	return time.Duration(n) * time.Second
}

func Ratio(s string) float64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return float64(v) / 100
}

func Same(s string) int {
	v, _ := strconv.ParseInt(s, 10, 64)
	// int(v) is fine on 64-bit; int32(v) would not be.
	return int(v)
}
