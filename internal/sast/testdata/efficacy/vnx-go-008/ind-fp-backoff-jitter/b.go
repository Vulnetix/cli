package retry

import (
	"math/rand"
	"time"
)

func Backoff(attempt int) time.Duration {
	base := time.Duration(1<<attempt) * 100 * time.Millisecond
	return base + time.Duration(rand.Int63n(int64(base)))
}
