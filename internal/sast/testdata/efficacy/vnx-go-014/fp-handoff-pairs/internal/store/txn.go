package store

import (
	"bytes"
	"io"
	"sync"
)

type Store struct {
	wmu  sync.Mutex
	rmu  sync.RWMutex
	data map[string]string
}

type Txn struct {
	s     *Store
	write bool
}

// NewTxn takes the lock the transaction holds until Commit or Abort.
func (s *Store) NewTxn(write bool) *Txn {
	if write {
		s.wmu.Lock()
	} else {
		s.rmu.RLock()
	}
	return &Txn{s: s, write: write}
}

func (t *Txn) Commit() {
	if t.write {
		t.s.wmu.Unlock()
		return
	}
	t.s.rmu.RUnlock()
}

type recordWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
	w   io.Writer
}

// start and end bracket one record; end releases the lock start took.
func (w *recordWriter) start() {
	w.mu.Lock()
	w.buf.WriteByte('{')
}

func (w *recordWriter) end() {
	w.buf.WriteByte('}')
	w.w.Write(w.buf.Bytes())
	w.buf.Reset()
	w.mu.Unlock()
}
