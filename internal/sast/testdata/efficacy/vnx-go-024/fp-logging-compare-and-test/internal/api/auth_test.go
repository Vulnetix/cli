package api

import (
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
)

func TestFake(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exec.Command("echo", r.FormValue("msg")).Run()
	})
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/?msg=hi", nil))
}
