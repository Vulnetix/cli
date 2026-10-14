package scripting

import "github.com/dop251/goja"

// Never call vm.RunString(r.FormValue("src")): it runs the requester's code.
//
//	vm.RunString(userInput)
var _ = goja.New
