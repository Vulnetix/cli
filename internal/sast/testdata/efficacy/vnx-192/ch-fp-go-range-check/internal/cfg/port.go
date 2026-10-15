package cfg

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
	if n < 0 || n > math.MaxUint16 {
		return 0, fmt.Errorf("port out of range: %d", n)
	}
	return uint16(n), nil
}
