package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFake(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<p>%s</p>", r.FormValue("x"))
	}))
	defer srv.Close()
}
