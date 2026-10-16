package web

import (
	"fmt"
	"html/template"
	"net/http"
)

func Search(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("q")
	msg := fmt.Sprintf("<b><i>%s</i></b> was not found", term)
~>	page.Execute(w, map[string]any{"Message": template.HTML(msg)})
}

var page = template.Must(template.New("s").Parse(`<p>{{.Message}}</p>`))
