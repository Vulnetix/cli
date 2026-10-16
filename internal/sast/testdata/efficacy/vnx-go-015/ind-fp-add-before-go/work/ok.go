package work

import "sync"

func Run(items []Item) {
	var wg sync.WaitGroup
	for _, item := range items {
		wg.Add(1)
		go func(i Item) {
			defer wg.Done()
			process(i)
		}(item)
	}
	wg.Wait()
}
