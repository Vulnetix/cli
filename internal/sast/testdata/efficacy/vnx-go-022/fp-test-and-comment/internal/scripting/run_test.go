package scripting

import (
	"net/http/httptest"
	"testing"

	"github.com/dop251/goja"
)

func TestRun(t *testing.T) {
	r := httptest.NewRequest("POST", "/run?src=1%2B1", nil)
	vm := goja.New()
	if _, err := vm.RunString(r.URL.Query().Get("src")); err != nil {
		t.Fatal(err)
	}
}
