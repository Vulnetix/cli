package ext

import (
	"net/http"
	"plugin"
)

func Load(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("plugin")
~>	p, err := plugin.Open("/opt/plugins/" + name + ".so")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_ = p
~>	q, _ := plugin.Open(r.FormValue("path"))
	_ = q
}
