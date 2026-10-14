package doc

import "strconv"

// n, _ := strconv.Atoi(s); return int32(n) truncates; check the range first.
const example = "n, _ := strconv.Atoi(s)\nreturn int32(n)"

func Safe(s string) int64 {
	n, _ := strconv.Atoi(s)
	// int32(n) would truncate here
	return int64(n)
}
