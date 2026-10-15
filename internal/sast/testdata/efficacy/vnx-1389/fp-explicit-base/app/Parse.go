package app

import "strconv"

func Parse(s string) (int64, error) {
	a, _ := strconv.ParseInt(s, 10, 64)
	b, _ := strconv.ParseUint(s, 16, 32)
	c, err := strconv.ParseInt("0x10", 0, 64)
	_ = b
	return a + c, err
}
