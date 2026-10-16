package render

import (
	"html/template"
	"io"
)

type Renderer struct{ t *template.Template }

func (r *Renderer) Render(w io.Writer, name string, data any) error {
	return r.t.ExecuteTemplate(w, name, data)
}
