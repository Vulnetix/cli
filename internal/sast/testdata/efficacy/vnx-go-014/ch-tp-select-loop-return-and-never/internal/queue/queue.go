package queue

import (
	"context"
	"sync"
)

type Config struct{ Size int }

var (
	cfgMu sync.Mutex
	cfg   Config
)

func SetConfig(c Config) {
~>	cfgMu.Lock()
	cfg = c
}

type Queue struct {
	mu     sync.Mutex
	closed bool
	buf    []string
}

func (q *Queue) Pump(ctx context.Context, ch <-chan string) {
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-ch:
~>			q.mu.Lock()
			if q.closed {
				return
			}
			q.buf = append(q.buf, m)
			q.mu.Unlock()
		}
	}
}
