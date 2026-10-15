package ext

import (
	"net/http"
	"path/filepath"
	"plugin"
)

func Load(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("ext")
	soPath := filepath.Join("/opt/app/plugins", name+".so")
~>	p, err := plugin.Open(soPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sym, _ := p.Lookup("Run")
	sym.(func())()
}
