package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = page.Execute(w, nil)
	}))
	defer srv.Close()
}
