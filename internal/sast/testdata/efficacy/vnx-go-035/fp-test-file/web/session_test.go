package web

import (
	"net/http"
	"testing"
)

func TestReadsCookie(t *testing.T) {
	ck := &http.Cookie{Name: "session", Value: "abc"}
	rec := newRecorder()
	http.SetCookie(rec, ck)
}
