package http

import (
	"strconv"
	"testing"
)

func TestPages(t *testing.T) {
	n, _ := strconv.Atoi("10")
	if got := 1000 / n; got != 100 {
		t.Fatal(got)
	}
}
