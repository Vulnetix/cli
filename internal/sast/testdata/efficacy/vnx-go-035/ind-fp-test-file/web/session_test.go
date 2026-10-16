package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCookie(t *testing.T) {
	w := httptest.NewRecorder()
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "x"})
}
