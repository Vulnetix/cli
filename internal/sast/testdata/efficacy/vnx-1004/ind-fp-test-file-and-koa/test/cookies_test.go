package handlers

import (
	"net/http"
	"testing"
)

func TestCookieShape(t *testing.T) {
	c := &http.Cookie{Name: "session", Value: "abc"}
	if c.HttpOnly {
		t.Fatal("expected default false")
	}
}
