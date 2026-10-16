package ext

import (
	"net/http"
	"path/filepath"
	"plugin"
)

func Load(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("ext")
	soPath := filepath.Join("/opt/acme/ext", name+".so")
~>	p, err := plugin.Open(soPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sym, err := p.Lookup("Register")
	if err != nil {
		http.Error(w, "no Register", http.StatusBadRequest)
		return
	}
	sym.(func())()
	w.WriteHeader(http.StatusNoContent)
}
