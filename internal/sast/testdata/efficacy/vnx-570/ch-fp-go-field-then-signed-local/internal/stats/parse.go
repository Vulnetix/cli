package stats

import "strconv"

type Counter struct {
	n uint32
}

func ParseDelta(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return -n, nil
	}
	return n, nil
}
