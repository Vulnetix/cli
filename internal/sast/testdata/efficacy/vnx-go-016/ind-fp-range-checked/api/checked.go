package api

import (
	"math"
	"strconv"
)

func Page(s string) (uint16, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > math.MaxUint16 {
		return 0, false
	}
	return uint16(n), true
}
