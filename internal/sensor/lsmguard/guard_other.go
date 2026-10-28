//go:build !linux

package lsmguard

import (
	"context"
	"errors"
)

// Guard is only available on Linux.
type Guard struct{}

// Load always fails off Linux.
func Load() (*Guard, error) { return nil, errors.New("the BPF LSM guard needs Linux") }

func (g *Guard) SetEnforce(bool) error                  { return nil }
func (g *Guard) Sync([]Entry, string) ([]string, error) { return nil, nil }
func (g *Guard) Run(context.Context, func(Refusal))     {}
func (g *Guard) Close()                                 {}
