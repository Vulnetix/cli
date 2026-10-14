package encode

import "sync"

type stream struct {
	wg      sync.WaitGroup
	writeWg sync.WaitGroup
	out     chan []byte
}

// The encoding goroutine is counted by s.wg; Close waits on s.wg before
// s.writeWg, so the writer's Add always precedes that Wait.
func (s *stream) push(block []byte) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.writeWg.Wait()
		s.writeWg.Add(1)
		go func() {
			defer s.writeWg.Done()
			s.out <- block
		}()
	}()
}

func (s *stream) Close() {
	s.wg.Wait()
	s.writeWg.Wait()
}
