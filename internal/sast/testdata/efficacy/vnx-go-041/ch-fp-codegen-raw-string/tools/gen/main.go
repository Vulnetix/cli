package main

import (
	"os"
	"text/template"
)

// The generated client is reviewed by hand; the template below only seeds it.
const clientTmpl = `package {{.Pkg}}

import "crypto/tls"

func legacyConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS11,
	}
}
`

func main() {
	t := template.Must(template.New("client").Parse(clientTmpl))
	_ = t.Execute(os.Stdout, map[string]string{"Pkg": "legacy"})
}
