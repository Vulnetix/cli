package net

import "strconv"

func Port(s string) (uint16, error) {
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(p), nil
}

func Small(s string) int8 {
	v, _ := strconv.ParseInt(s, 10, 8)
	return int8(v)
}
