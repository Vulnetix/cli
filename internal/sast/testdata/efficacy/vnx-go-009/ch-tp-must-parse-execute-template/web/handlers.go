package web

import (
	"log"
	"net/http"
	"text/template"
)

const pageSrc = `<html><body><h1>Hello {{.Name}}</h1><p>{{.Bio}}</p></body></html>`

var page = template.Must(template.New("profile").Parse(pageSrc))

type profile struct {
	Name string
	Bio  string
}

func ProfileHandler(rw http.ResponseWriter, req *http.Request) {
	p := profile{
		Name: req.URL.Query().Get("name"),
		Bio:  req.FormValue("bio"),
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
~>	if err := page.ExecuteTemplate(rw, "profile", p); err != nil {
		log.Printf("render: %v", err)
	}
}
