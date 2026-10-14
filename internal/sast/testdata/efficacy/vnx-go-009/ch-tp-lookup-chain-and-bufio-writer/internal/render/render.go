package render

import (
	"bufio"
	"net/http"
	"text/template"
)

var site = template.Must(template.New("site").Parse(`{{define "row"}}<tr><td>{{.}}</td></tr>{{end}}`))

func Row(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("v")
~>	site.Lookup("row").Execute(w, v)
}

func Rows(w http.ResponseWriter, r *http.Request) {
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	for _, v := range r.URL.Query()["v"] {
~>		site.ExecuteTemplate(bw, "row", v)
	}
}
