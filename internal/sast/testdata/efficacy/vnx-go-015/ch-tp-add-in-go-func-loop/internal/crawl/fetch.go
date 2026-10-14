package crawl

import (
	"net/http"
	"sync"
)

func FetchAll(urls []string) []int {
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		codes []int
	)
	for _, u := range urls {
		go func(u string) {
~>			wg.Add(1)
			defer wg.Done()
			resp, err := http.Get(u)
			if err != nil {
				return
			}
			resp.Body.Close()
			mu.Lock()
			codes = append(codes, resp.StatusCode)
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	return codes
}
