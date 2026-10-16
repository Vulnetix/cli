package work

import "sync"

func Run(items []Item) {
	var wg sync.WaitGroup
	for _, item := range items {
		go func(i Item) {
~>			wg.Add(1)
			defer wg.Done()
			process(i)
		}(item)
	}
	wg.Wait()
}
