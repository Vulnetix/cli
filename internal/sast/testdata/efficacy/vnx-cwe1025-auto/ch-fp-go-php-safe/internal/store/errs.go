package store

import (
	"errors"
	"io"
	"log"
)

var ErrMissing = errors.New("missing")

func handle(err error) bool {
	if err == io.EOF || errors.Is(err, ErrMissing) {
		return true
	}
	var pe *PathError
	if errors.As(err, &pe) {
		return false
	}
	if err != nil && err.Error() != "" {
		log.Printf("error: %v", err)
	}
	return false
}

type PathError struct{ Path string }

func (p *PathError) Error() string { return p.Path }
