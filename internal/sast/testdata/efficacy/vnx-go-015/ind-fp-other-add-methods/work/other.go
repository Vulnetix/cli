package work

import (
	"sync"
	"sync/atomic"
	"time"
)

func Count(n int) int64 {
	var total atomic.Int64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			total.Add(1)
			deadline := time.Now().Add(time.Second)
			_ = deadline
		}()
	}
	wg.Wait()
	return total.Load()
}
