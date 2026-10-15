package handlers

import (
	"html/template"
	"net/http"

	"github.com/russross/blackfriday/v2"
)

var preview = template.Must(template.ParseFiles("preview.html"))

func Preview(w http.ResponseWriter, r *http.Request) {
	src := r.PostFormValue("markdown")
	rendered := blackfriday.Run([]byte(src))
~>	safe := template.HTML(rendered)
	preview.Execute(w, safe)
}
