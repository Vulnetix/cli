package web

import (
	"html/template"
	"net/http"

	"github.com/microcosm-cc/bluemonday"
)

var policy = bluemonday.UGCPolicy()

func Comment(w http.ResponseWriter, r *http.Request) {
	body := r.FormValue("body")
	data := map[string]any{"Body": template.HTML(policy.Sanitize(body))}
	tpl.Execute(w, data)
}

var tpl = template.Must(template.New("c").Parse(`<div>{{.Body}}</div>`))
