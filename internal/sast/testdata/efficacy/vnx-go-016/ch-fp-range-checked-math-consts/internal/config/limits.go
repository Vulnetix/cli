package config

import (
	"fmt"
	"math"
	"strconv"
)

func Port(s string) (uint16, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if n < 1 || n > math.MaxUint16 {
		return 0, fmt.Errorf("port %d out of range", n)
	}
	return uint16(n), nil
}

func Weight(s string) (int32, error) {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if v > math.MaxInt32 || v < math.MinInt32 {
		return 0, fmt.Errorf("weight %d overflows int32", v)
	}
	return int32(v), nil
}

func Retries(s string) uint8 {
	r, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 3
	}
	return uint8(r)
}

func Shard(s string) int32 {
	x, _ := strconv.ParseInt(s, 10, 32)
	return int32(x)
}
