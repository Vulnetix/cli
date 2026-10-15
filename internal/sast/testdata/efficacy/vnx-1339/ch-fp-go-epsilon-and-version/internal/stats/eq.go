package stats

import "math"

const eps = 1e-9

func Near(a float64) bool {
	return math.Abs(a-0.1) < eps
}

func Supported(v string) bool {
	return v == "0.1" || v == "1.3"
}
