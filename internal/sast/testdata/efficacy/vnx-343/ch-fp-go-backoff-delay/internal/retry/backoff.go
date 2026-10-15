package retry

import (
	"math/rand"
	"time"
)

func nextDelay(prevDelay, jitter time.Duration) time.Duration {
	delay := prevDelay + time.Duration(rand.Int63n(int64(jitter)))
	return delay
}
