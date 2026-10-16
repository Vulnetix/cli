package net

import (
	"errors"
	"io"
)

func done(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}
	if err.Error() != "" {
		return false
	}
	return false
}
