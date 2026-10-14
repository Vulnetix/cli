package web

import (
	"html"
	"html/template"
	"net/http"

	"github.com/microcosm-cc/bluemonday"
)

var policy = bluemonday.UGCPolicy()

// The user's markup goes through an HTML sanitiser or an escaper before it is
// marked safe.
func Comment(w http.ResponseWriter, r *http.Request) {
	body := r.FormValue("body")
	data := map[string]any{}
	data["Body"] = template.HTML(policy.Sanitize(body))
	data["Strict"] = template.HTML(bluemonday.StrictPolicy().Sanitize(r.FormValue("title")))
	data["Name"] = template.HTML(html.EscapeString(r.FormValue("name")))
	data["Sig"] = template.HTML(template.HTMLEscapeString(r.FormValue("sig")))
	clean := policy.Sanitize(r.FormValue("bio"))
	data["Bio"] = template.HTML(clean)
	data["Next"] = template.JSEscapeString(r.FormValue("next"))
	_ = data
}
