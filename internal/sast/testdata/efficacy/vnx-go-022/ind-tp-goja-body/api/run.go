package api

import (
	"io"
	"net/http"

	"github.com/dop251/goja"
)

func Run(w http.ResponseWriter, r *http.Request) {
	vm := goja.New()
	src, _ := io.ReadAll(r.Body)
~>	v, err := vm.RunString(string(src))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Write([]byte(v.String()))
}
