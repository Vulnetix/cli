package stats

import "strconv"

func Mean(xs []string) float64 {
	var sum int64
	for _, s := range xs {
		n, err := strconv.Atoi(s)
		if err != nil {
			continue
		}
		sum += int64(n)
	}
	return float64(sum) / float64(len(xs))
}

func Width(n int) int32 {
	return int32(n)
}

func Count(s string, items []string) int32 {
	n, _ := strconv.Atoi(s)
	_ = n
	k := len(items)
	return int32(k)
}

func Big(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return uint64(v) + uint64(len(s))
}
