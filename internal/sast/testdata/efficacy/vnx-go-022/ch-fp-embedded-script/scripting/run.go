package scripting

import (
	_ "embed"

	"github.com/dop251/goja"
	lua "github.com/yuin/gopher-lua"
)

//go:embed bootstrap.js
var bootstrap string

const luaInit = `print("ready")`

func Start() error {
	vm := goja.New()
	if _, err := vm.RunString(bootstrap); err != nil {
		return err
	}
	L := lua.NewState()
	defer L.Close()
	return L.DoString(luaInit)
}
