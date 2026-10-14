package store

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
)

var errBusy = errors.New("busy")

func shouldRetry(err error) bool {
	if err == nil || err == io.EOF {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errBusy) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "reset by peer") || msg != ""
}

func sameType(a, b interface{}) bool {
	return reflect.TypeOf(a) == reflect.TypeOf(b)
}
