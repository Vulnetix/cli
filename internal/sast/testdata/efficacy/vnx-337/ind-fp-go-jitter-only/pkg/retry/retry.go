package retry

import (
	"math/rand"
	"time"
)

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

// Sleep waits for a jittered interval before the next poll.
func Sleep(base time.Duration) {
	time.Sleep(base + time.Duration(rng.Int63n(int64(base))))
}
