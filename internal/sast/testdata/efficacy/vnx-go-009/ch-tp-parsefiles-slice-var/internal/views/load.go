package views

import (
	"path/filepath"
	"text/template"
)

func Load(dir string) (*template.Template, error) {
	files := []string{"layout.html", "nav.html", "index.html"}
	for i, f := range files {
		files[i] = filepath.Join(dir, f)
	}
~>	return template.ParseFiles(files...)
}
