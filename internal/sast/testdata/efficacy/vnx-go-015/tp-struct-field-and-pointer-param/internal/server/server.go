package server

import (
	"net"
	"sync"
)

type Server struct {
	ln       net.Listener
	inflight sync.WaitGroup
}

// Serve counts connections from inside the handler goroutine, so Shutdown's
// Wait can see zero while a connection is already being served.
func (s *Server) Serve(handle func(net.Conn)) {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go func() {
~>			s.inflight.Add(1)
			defer s.inflight.Done()
			handle(c)
		}()
	}
}

func (s *Server) Shutdown() {
	s.ln.Close()
	s.inflight.Wait()
}

func spawn(jobs []func(), group *sync.WaitGroup) {
	for _, j := range jobs {
		go func() {
~>			group.Add(1)
			defer group.Done()
			j()
		}()
	}
}
