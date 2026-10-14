package workers

import "sync"

func Background(parts [][]int, sum func([]int) int, out chan<- int) {
	go func() {
		var inner sync.WaitGroup
		results := make([]int, len(parts))
		for i, p := range parts {
			inner.Add(1)
			go func(i int, p []int) {
				defer inner.Done()
				results[i] = sum(p)
			}(i, p)
		}
		inner.Wait()
		for _, r := range results {
			out <- r
		}
		close(out)
	}()
}

func Release(wg *sync.WaitGroup) {
	go func() {
		// wg.Add(1) here would race with Wait; we only release.
		wg.Add(-1)
	}()
}
