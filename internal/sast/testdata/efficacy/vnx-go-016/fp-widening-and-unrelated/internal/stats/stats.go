package stats

import (
	"strconv"
	"time"
)

// Widening conversions and conversions of other values near a parse.
func Parse(count, ms string, raw []byte) (int64, float64, time.Duration, uint32) {
	n, _ := strconv.Atoi(count)
	total := int64(n)
	ratio := float64(n) / 3
	v, _ := strconv.ParseInt(ms, 10, 64)
	d := time.Duration(v) * time.Millisecond
	checksum := uint32(len(raw))
	return total, ratio, d, checksum
}
