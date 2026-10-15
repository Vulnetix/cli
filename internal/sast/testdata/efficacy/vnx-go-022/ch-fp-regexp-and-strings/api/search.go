package api

import (
	"html/template"
	"net/http"
	"regexp"
	"time"
)

var page = template.Must(template.New("search").Parse(`<p>{{.}}</p>`))

func Search(w http.ResponseWriter, r *http.Request) {
	re, err := regexp.Compile(regexp.QuoteMeta(r.FormValue("q")))
	if err != nil {
		return
	}
	when, _ := time.Parse(time.RFC3339, r.FormValue("since"))
	_ = when
	page.Execute(w, re.String())
}
