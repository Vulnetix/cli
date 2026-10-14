package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	http.SetCookie(rec, &http.Cookie{Name: "session", Value: "x"})
	if rec.Header().Get("Set-Cookie") == "" {
		t.Fatal("no cookie")
	}
}
