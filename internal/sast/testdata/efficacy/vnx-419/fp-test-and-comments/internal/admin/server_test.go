package admin

import (
	"net/http"
	"testing"
)

func TestAdmin(t *testing.T) {
	go http.ListenAndServe(":9090", adminMux)
}
