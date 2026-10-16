package jitter

import (
	"math/rand"
	"time"
)

var src = rand.New(rand.NewSource(time.Now().UnixNano()))

// Backoff returns the delay before the next retry attempt.
func Backoff(attempt int) time.Duration {
	base := time.Duration(1<<attempt) * 100 * time.Millisecond
	return base + time.Duration(src.Int63n(int64(base/2)))
}
