package web

import (
	"html/template"
	"net/http"
)

const betaBanner = `<span class="beta">Beta</span>`

var footer = "<footer>&copy; Example Ltd</footer>"

// Markup written by the developer is the case template.HTML exists for.
func Login(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	if r.FormValue("username") == "" {
		data["Message"] = template.HTML("<div class=\"alert alert-danger\"><p>Empty username or password</p></div>")
	} else {
		data["Message"] = template.HTML(`<div class="alert">Signed in</div>`)
	}
	data["Banner"] = template.HTML(betaBanner)
	data["Footer"] = template.HTML(footer)
	data["Rule"] = template.HTML("<hr>" + "<br>")
	data["Empty"] = template.HTML("")
	data["Home"] = template.URL("/")
	data["Init"] = template.JS(`window.app = {};`)
	_ = data
}
