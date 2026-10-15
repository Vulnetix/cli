package backoff

import (
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func Jitter(base time.Duration) time.Duration {
	return base + time.Duration(rand.Int63n(int64(base)))
}
