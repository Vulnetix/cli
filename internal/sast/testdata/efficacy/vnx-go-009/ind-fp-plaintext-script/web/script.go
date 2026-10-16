package web

import (
	"net/http"
	"text/template"
)

var installer = template.Must(template.New("sh").Parse("#!/bin/sh\necho installing {{.Version}}\n"))

func Install(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript")
	installer.Execute(w, map[string]string{"Version": "1.2.3"})
}
