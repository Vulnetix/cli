package main

import (
	"net/http/httptest"
	_ "net/http/pprof"
	"testing"
)

func TestServe(t *testing.T) {
	srv := httptest.NewServer(nil)
	defer srv.Close()
}
