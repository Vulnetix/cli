package web

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

// The term is formatted into markup by hand and the result is marked safe.
func Search(w http.ResponseWriter, r *http.Request) {
	term := r.FormValue("term")
	term = strings.TrimSpace(term)
	notFound := fmt.Sprintf("<b><i>%s</i></b> was not found", term)
	data := map[string]any{}
~>	data["Message"] = template.HTML(notFound)
	render(w, data)
}

// The id reaches inline script through a format string.
func Card(w http.ResponseWriter, r *http.Request) {
	uid := r.URL.Query().Get("uid")
	js := `<script>var id = %s;</script>`
	inline := fmt.Sprintf(js, uid)
	data := map[string]any{
~>		"Inline": template.HTML(inline),
	}
	render(w, data)
}

func render(w http.ResponseWriter, data map[string]any) {}
