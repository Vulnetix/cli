package scripting

import (
	_ "embed"

	"github.com/dop251/goja"
	lua "github.com/yuin/gopher-lua"
)

//go:embed prelude.js
var prelude string

const shim = `var console = { log: function() {} };`

// Scripts that ship with the program are not injected code.
func Boot() (*goja.Runtime, error) {
	vm := goja.New()
	if _, err := vm.RunString(shim); err != nil {
		return nil, err
	}
	if _, err := vm.RunString(prelude); err != nil {
		return nil, err
	}
	if _, err := vm.RunString("1 + 1"); err != nil {
		return nil, err
	}
	_, err := vm.RunScript("prelude.js", prelude)
	return vm, err
}

func Lua() error {
	L := lua.NewState()
	defer L.Close()
	return L.DoString(`print("ready")`)
}
