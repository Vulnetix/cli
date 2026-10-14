package fetch

import "sync"

func All(urls []string, get func(string) []byte) [][]byte {
	out := make([][]byte, len(urls))
	wg := &sync.WaitGroup{}
	for i, u := range urls {
		go func(i int, u string) {
~>			wg.Add(1)
			defer wg.Done()
			out[i] = get(u)
		}(i, u)
	}
	wg.Wait()
	return out
}
