package accounts

import (
	"errors"
	"sync"
)

var (
	ErrUnknown      = errors.New("unknown account")
	ErrInsufficient = errors.New("insufficient funds")
)

type Ledger struct {
	mu       sync.Mutex
	balances map[string]int64
}

func (l *Ledger) Withdraw(id string, amt int64) error {
~>	l.mu.Lock()
	bal, ok := l.balances[id]
	if !ok {
		l.mu.Unlock()
		return ErrUnknown
	}
	if bal < amt {
		return ErrInsufficient
	}
	l.balances[id] = bal - amt
	l.mu.Unlock()
	return nil
}
