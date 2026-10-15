package web

import (
	"net/http"
	"strings"
	"text/template"
)

var funcs = template.FuncMap{"upper": strings.ToUpper}

func Render(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("layout")
~>	tmpl, err := template.New("page").Funcs(funcs).Parse(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tmpl.Execute(w, nil)
}
