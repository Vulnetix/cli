package proto

import (
	"errors"
	"strconv"
)

var errRange = errors.New("out of range")

func Weight(s string) (int32, error) {
	v, err := strconv.ParseInt(
		s, 10, 32)
	if err != nil {
		return 0, err
	}
	return int32(v), nil
}

func Port(s string) (uint16, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if n < 0 || n > 1<<16-1 {
		return 0, errRange
	}
	return uint16(n), nil
}

func Mask(s string) (uint16, error) {
	v, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return 0, err
	}
	if v < 0 || v > 0xffff {
		return 0, errRange
	}
	return uint16(v), nil
}
