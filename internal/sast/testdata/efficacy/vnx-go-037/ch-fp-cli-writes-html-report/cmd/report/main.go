package main

import (
	"flag"
	"html/template"
	"log"
	"os"
)

var tmpl = template.Must(template.New("r").Parse(`<html><body>{{.}}</body></html>`))

func main() {
	out := flag.String("o", "report.html", "output file")
	flag.Parse()
	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if err := tmpl.Execute(f, flag.Args()); err != nil {
		log.Fatal(err)
	}
}
