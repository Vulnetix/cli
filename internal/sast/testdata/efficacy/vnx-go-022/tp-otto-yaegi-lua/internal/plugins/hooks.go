package plugins

import (
	"net/http"

	"github.com/robertkrimen/otto"
	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
	lua "github.com/yuin/gopher-lua"
)

func OttoHook(w http.ResponseWriter, r *http.Request) {
	vm := otto.New()
	hook := r.FormValue("hook")
~>	vm.Run(hook)
}

// yaegi with the standard library loaded is a full Go interpreter: os/exec
// included.
func GoHook(w http.ResponseWriter, r *http.Request) {
	i := interp.New(interp.Options{})
	i.Use(stdlib.Symbols)
	code := r.PostFormValue("code")
~>	if _, err := i.Eval(code); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func LuaHook(script string) error {
	L := lua.NewState()
	defer L.Close()
~>	return L.DoString(script)
}
