package main

import (
	"flag"
	"os"
	"text/template"
)

const usage = `Usage: report [flags]
{{range .}}  -{{.Name}}	{{.Usage}}
{{end}}`

func main() {
	t := template.Must(template.New("usage").Parse(usage))
	var flags []*flag.Flag
	flag.VisitAll(func(f *flag.Flag) { flags = append(flags, f) })
	// t.Execute(w, flags) would be wrong for a web handler; this is a terminal.
	t.Execute(os.Stdout, flags)
	msg := "never call text/template Execute(w, data) into an http.ResponseWriter"
	_ = msg
}
