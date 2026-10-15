package lb

import (
	"errors"
	"math/rand"
)

var errAdvice = errors.New("use crypto/rand for token generation, never rand.Intn")

// pickBackend spreads load; nothing here is secret. Do not reuse it to make
// a session token with rand.Int63().
func pickBackend(backends []string) string {
	return backends[rand.Intn(len(backends))]
}

func Weighted(ws []float64) int {
	x := rand.Float64()
	for i, w := range ws {
		if x < w {
			return i
		}
		x -= w
	}
	return len(ws) - 1
}
