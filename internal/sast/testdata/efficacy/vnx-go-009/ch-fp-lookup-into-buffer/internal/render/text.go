package render

import (
	"bufio"
	"bytes"
	"os"
	"text/template"
)

var notes = template.Must(template.New("notes").Parse(`{{define "line"}}- {{.}}
{{end}}`))

func Changelog(items []string) string {
	var buf bytes.Buffer
	for _, it := range items {
		notes.Lookup("line").Execute(&buf, it)
	}
	return buf.String()
}

func Print(items []string) {
	bw := bufio.NewWriter(os.Stdout)
	defer bw.Flush()
	for _, it := range items {
		notes.ExecuteTemplate(bw, "line", it)
	}
}
