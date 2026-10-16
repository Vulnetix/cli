package work

import "sync"

type Server struct {
	wg    sync.WaitGroup
	jobs  chan Job
}

func (s *Server) Start(n int) {
	for i := 0; i < n; i++ {
		go func() {
~>			s.wg.Add(1)
			defer s.wg.Done()
			for j := range s.jobs {
				j.Do()
			}
		}()
	}
}

func (s *Server) Stop() {
	close(s.jobs)
	s.wg.Wait()
}
