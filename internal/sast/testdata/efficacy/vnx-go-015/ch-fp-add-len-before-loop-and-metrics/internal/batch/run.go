package batch

import (
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

var processed = prometheus.NewCounter(prometheus.CounterOpts{Name: "processed_total"})

func Run(items []string, f func(string)) int64 {
	var wg sync.WaitGroup
	var n atomic.Int64
	var total int64
	wg.Add(len(items))
	for _, it := range items {
		go func(it string) {
			defer wg.Done()
			f(it)
			n.Add(1)
			atomic.AddInt64(&total, 1)
			processed.Add(1)
		}(it)
	}
	wg.Wait()
	return n.Load() + total
}
