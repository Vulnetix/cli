package conn

import (
	"errors"
	"sync"
)

var ErrClosed = errors.New("pool closed")

type Conn struct{ id int }

type Pool struct {
	mu     sync.Mutex
	closed bool
	idle   []*Conn
	max    int
}

func (p *Pool) Put(c *Conn) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return ErrClosed
	} else {
		p.idle = append(p.idle, c)
		p.mu.Unlock()
	}
	if len(p.idle) > p.max {
		return errors.New("over capacity")
	}
	return nil
}

func (p *Pool) State() string {
	p.mu.Lock()
	switch {
	case p.closed:
		p.mu.Unlock()
		return "closed"
	case len(p.idle) == 0:
		p.mu.Unlock()
		return "empty"
	}
	n := len(p.idle)
	p.mu.Unlock()
	if n > 10 {
		return "busy"
	}
	return "ok"
}

func (p *Pool) Get() (*Conn, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrClosed
	}
	if len(p.idle) == 0 {
		p.mu.Unlock()
		return &Conn{}, nil
	}
	c := p.idle[0]
	p.idle = p.idle[1:]
	p.mu.Unlock()
	return c, nil
}
