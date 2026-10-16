package web

import (
	"html/template"
	"net/http"
)

func Profile(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	bio := r.FormValue("bio")
~>	data["Bio"] = template.HTML(bio)
	tpl.Execute(w, data)
}

var tpl = template.Must(template.New("p").Parse(`<div>{{.Bio}}</div>`))
