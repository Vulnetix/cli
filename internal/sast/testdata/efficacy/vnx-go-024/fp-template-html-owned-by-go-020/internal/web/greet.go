package web

import (
	"fmt"
	"html/template"
	"net/http"
)

var greetPage = template.Must(template.New("g").Parse(`<h1>{{.Hello}}</h1><script>{{.Boot}}</script><a href="{{.Next}}">next</a>`))

// Marking request data as trusted markup is VNX-GO-020's finding; this rule
// does not report the same line a second time.
func Greet(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	hello := fmt.Sprintf("Hello, <em>%s</em>", name)
	next := r.URL.Query().Get("next")
	data := map[string]any{
		"Hello": template.HTML(hello),
		"Boot":  template.JS(r.FormValue("boot")),
		"Next":  template.URL(next),
	}
	greetPage.Execute(w, data)
}
