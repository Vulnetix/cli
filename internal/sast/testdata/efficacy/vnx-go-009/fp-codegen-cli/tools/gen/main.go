// Command gen writes the enum tables. text/template is the right package for
// Go source, YAML and shell; html/template would mangle them.
package main

import (
	"bytes"
	"go/format"
	"log"
	"os"
	"text/template"
)

var src = template.Must(template.New("enum").Parse(`package {{.Pkg}}

const (
{{range .Names}}	{{.}} = "{{.}}"
{{end}})
`))

var helm = template.Must(template.ParseFiles("charts/values.yaml.tmpl"))

func main() {
	var buf bytes.Buffer
	if err := src.Execute(&buf, map[string]any{"Pkg": "kinds", "Names": os.Args[1:]}); err != nil {
		log.Fatal(err)
	}
	out, err := format.Source(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Create("kinds_gen.go")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	f.Write(out)

	w := os.Stdout
	helm.Execute(w, nil)
}
