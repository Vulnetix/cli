package ingest

import "sync"

type Record struct{ ID string }

func Process(src []Record, workers int, handle func(Record)) {
	var pending sync.WaitGroup
	queue := make(chan Record)

	go func() {
		for _, rec := range src {
~>			pending.Add(1)
			queue <- rec
		}
		close(queue)
	}()

	for i := 0; i < workers; i++ {
		go func() {
			for rec := range queue {
				handle(rec)
				pending.Done()
			}
		}()
	}
	pending.Wait()
}
