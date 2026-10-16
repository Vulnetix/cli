package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	http.SetCookie(rec, &http.Cookie{Name: "a", Value: "b"})
	if rec.Header().Get("Set-Cookie") == "" {
		t.Fatal("none")
	}
}
