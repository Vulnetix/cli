package api

import (
	"net/http"
	"text/template"
)

func Preview(w http.ResponseWriter, r *http.Request) {
	body := r.FormValue("template")
~>	t, err := template.New("preview").Parse(body)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	t.Execute(w, nil)
}
