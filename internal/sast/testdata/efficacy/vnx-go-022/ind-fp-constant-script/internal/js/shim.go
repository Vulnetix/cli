package js

import (
	_ "embed"

	"github.com/dop251/goja"
)

//go:embed shim.js
var shim string

func Setup() (*goja.Runtime, error) {
	vm := goja.New()
	if _, err := vm.RunString(shim); err != nil {
		return nil, err
	}
	_, err := vm.RunString(`var version = "1.0";`)
	return vm, err
}
