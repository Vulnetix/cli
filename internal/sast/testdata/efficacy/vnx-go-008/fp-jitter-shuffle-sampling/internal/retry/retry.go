package retry

import (
	"math/rand"
	"time"
)

// RefreshToken retries the token endpoint with jittered backoff.
func RefreshToken(fetch func() error) error {
	delay := 100 * time.Millisecond
	for attempt := 0; attempt < 5; attempt++ {
		if err := fetch(); err == nil {
			return nil
		}
		jitter := time.Duration(rand.Int63n(int64(delay)))
		time.Sleep(delay + jitter)
		delay *= 2
	}
	return errExhausted
}

func Sample(rate float64) bool {
	return rand.Float64() < rate
}

func shuffleQuestions(qs []string) {
	rand.Shuffle(len(qs), func(i, j int) { qs[i], qs[j] = qs[j], qs[i] })
}
