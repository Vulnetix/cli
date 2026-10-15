package main

import "strconv"

func f(s string) int64 {
	n, _ := strconv.Atoi(s)
	x := float64(n)
	y := int64(n)
	return y + int64(x)
}
