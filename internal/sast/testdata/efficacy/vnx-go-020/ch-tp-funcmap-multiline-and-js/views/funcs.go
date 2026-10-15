package views

import (
	"fmt"
	"html/template"
)

var Funcs = template.FuncMap{
	"raw": func(s string) template.HTML {
~>		return template.HTML(s)
	},
	"attr": func(name, value string) template.HTMLAttr {
~>		return template.HTMLAttr(name + `="` + value + `"`)
	},
}

func InitScript(username string) template.JS {
~>	return template.JS(fmt.Sprintf("window.currentUser = '%s';", username))
}
