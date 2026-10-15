package api

import (
	"math"
	"strconv"
)

func parse(s string) (int32, uint16, int16) {
	limit, err := strconv.Atoi(s)
	if err != nil || limit < 0 || limit > math.MaxInt32 {
		return 0, 0, 0
	}
	a := int32(limit)
	p, _ := strconv.ParseUint(s, 10, 16)
	b := uint16(p)
	q, _ := strconv.ParseInt(s, 10, 16)
	c := int16(q)
	n := int64(limit)
	_ = n
	return a, b, c
}
