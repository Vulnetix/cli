package stats

import (
	"math/big"
	"sync/atomic"
	"time"
)

type Stats struct {
	hits   atomic.Int64
	misses int64
	seen   map[string]struct{}
}

func (s *Stats) Record(keys []string, deadline time.Time) {
	go func() {
		s.hits.Add(1)
		atomic.AddInt64(&s.misses, 1)
		_ = deadline.Add(time.Minute)
		total := new(big.Int)
		total.Add(total, big.NewInt(2))
	}()
}
