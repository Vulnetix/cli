package web

import (
	"html"
	"html/template"
	"net/http"

	"github.com/microcosm-cc/bluemonday"
)

var policy = bluemonday.UGCPolicy()

func Comment(w http.ResponseWriter, r *http.Request) map[string]any {
	clean := policy.Sanitize(r.FormValue("comment"))
	return map[string]any{
		"Body":  template.HTML(clean),
		"Inline": template.HTML(policy.Sanitize(r.FormValue("sig"))),
		"Title": template.HTML("<em>" + html.EscapeString(r.FormValue("title")) + "</em>"),
	}
}
