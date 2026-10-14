package site

import (
	"html/template"
	"net/http"
	texttemplate "text/template"
)

var page = template.Must(template.New("p").Parse(`<p>{{.}}</p>`))

// banner was meant for the plain-text status endpoint but is served as HTML.
var banner = texttemplate.Must(texttemplate.New("b").Parse(`<marquee>{{.}}</marquee>`))

func Page(w http.ResponseWriter, r *http.Request) {
	page.Execute(w, r.URL.Query().Get("msg"))
}

func Banner(w http.ResponseWriter, r *http.Request) {
~>	banner.Execute(w, r.URL.Query().Get("msg"))
}
