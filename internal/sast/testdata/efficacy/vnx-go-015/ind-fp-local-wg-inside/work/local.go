package work

import "sync"

func Outer(batches [][]Item) {
	var done sync.WaitGroup
	for _, b := range batches {
		done.Add(1)
		go func(b []Item) {
			defer done.Done()
			var inner sync.WaitGroup
			for _, it := range b {
				inner.Add(1)
				go func(it Item) {
					defer inner.Done()
					process(it)
				}(it)
			}
			inner.Wait()
		}(b)
	}
	done.Wait()
}
