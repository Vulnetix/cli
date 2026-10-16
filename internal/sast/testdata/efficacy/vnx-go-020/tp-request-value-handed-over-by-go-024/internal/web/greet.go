package web

import (
	"fmt"
	"html/template"
	"net/http"
)

var greetPage = template.Must(template.New("g").Parse(`<h1>{{.Hello}}</h1><script>{{.Boot}}</script><a href="{{.Next}}">next</a>`))

// Request data marked as trusted markup, script and URL. VNX-GO-024 leaves
// these lines to this rule.
func Greet(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	hello := fmt.Sprintf("Hello, <em>%s</em>", name)
	next := r.URL.Query().Get("next")
	data := map[string]any{
~>		"Hello": template.HTML(hello),
~>		"Boot":  template.JS(r.FormValue("boot")),
~>		"Next":  template.URL(next),
	}
	greetPage.Execute(w, data)
}
