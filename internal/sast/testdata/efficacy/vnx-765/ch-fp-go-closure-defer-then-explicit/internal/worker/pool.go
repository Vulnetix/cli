package worker

import "sync"

var (
	mu    sync.Mutex
	total int
)

func Process(xs []int) {
	for _, x := range xs {
		func() {
			mu.Lock()
			defer mu.Unlock()
			total += x
		}()
	}
	mu.Lock()
	total++
	mu.Unlock()
}

func Each(xs []int, fn func(int)) {
	for _, x := range xs {
		mu.Lock()
		fn(x)
		mu.Unlock()
	}
	mu.Lock()
	total = 0
	mu.Unlock()
}
