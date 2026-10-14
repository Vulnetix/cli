package view

import "html/template"

// A template helper that marks whatever its caller passes as safe turns off
// escaping for every template that uses it.
func Unescaped(s string) template.HTML {
~>	return template.HTML(s)
}

var Funcs = template.FuncMap{
~>	"raw":  func(s string) template.HTML { return template.HTML(s) },
~>	"safe": func(v any) template.HTMLAttr { return template.HTMLAttr(v.(string)) },
}
