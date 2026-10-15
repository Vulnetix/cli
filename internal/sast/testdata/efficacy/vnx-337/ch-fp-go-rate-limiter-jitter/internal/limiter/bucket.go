package limiter

import (
	"math/rand"
	"time"
)

type Bucket struct {
	tokens   float64
	capacity float64
	rng      *rand.Rand
}

func New(capacity float64) *Bucket {
	return &Bucket{
		tokens:   capacity,
		capacity: capacity,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (b *Bucket) Backoff(base time.Duration) time.Duration {
	b.tokens -= 1
	return base + time.Duration(b.rng.Int63n(int64(base)))
}
