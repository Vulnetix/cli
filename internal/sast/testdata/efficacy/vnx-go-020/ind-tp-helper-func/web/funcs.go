package web

import "html/template"

var funcs = template.FuncMap{
~>	"raw": func(s string) template.HTML { return template.HTML(s) },
}
