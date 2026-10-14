package scripting

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/dop251/goja"
)

// The request body is JavaScript and the server runs it.
func Run(w http.ResponseWriter, r *http.Request) {
	src, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	vm := goja.New()
~>	v, err := vm.RunString(string(src))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(v.Export())
}

type job struct {
	Name   string `json:"name"`
	Script string `json:"script"`
}

func Submit(w http.ResponseWriter, r *http.Request) {
	var j job
	if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
		return
	}
~>	prg, err := goja.Compile(j.Name, j.Script, true)
	if err != nil {
		return
	}
	goja.New().RunProgram(prg)
}

// A function that runs whatever text its caller hands it.
func Eval(rt *goja.Runtime, code string) (goja.Value, error) {
~>	return rt.RunScript("user.js", code)
}
