package cfg

import "strconv"

func Parse(s, t string) (int16, uint8, error) {
	n, err := strconv.ParseInt(s, 10, 16)
	if err != nil {
		return 0, 0, err
	}
	u, err := strconv.ParseUint(t, 10, 8)
	if err != nil {
		return 0, 0, err
	}
	return int16(n), uint8(u), nil
}
