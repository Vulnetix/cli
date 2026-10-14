package web

import (
	"html/template"
	"net/http"
)

var page = template.Must(template.New("p").Parse(`<div>{{.Bio}}</div>{{.Q}}`))

func Profile(w http.ResponseWriter, r *http.Request) {
	bio := r.FormValue("bio")
	data := map[string]any{}
~>	data["Bio"] = template.HTML(bio)
~>	data["Q"] = template.HTML(r.URL.Query().Get("q"))
	page.Execute(w, data)
}
