package main

import (
	"net/http"
	"testing"
)

func TestAdminServer(t *testing.T) {
	adminMux := http.NewServeMux()
	go http.ListenAndServe(":19090", adminMux)
}
