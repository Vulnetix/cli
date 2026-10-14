package install

import (
	"net/http"
	"text/template"
)

var installer = template.Must(template.New("install.sh").Parse(`#!/bin/sh
set -eu
curl -fsSL https://dl.example.com/{{.Version}}/agent -o /usr/local/bin/agent
`))

var cloudInit = template.Must(template.New("ci").Parse("#cloud-config\nhostname: {{.Host}}\n"))

func Script(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	installer.Execute(w, map[string]string{"Version": "1.4.2"})
}

func CloudInit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/cloud-config")
	cloudInit.Execute(w, map[string]string{"Host": "node-1"})
}
