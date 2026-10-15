package views

import (
	"html/template"
	"strconv"
	"strings"
)

func Indent(depth int) template.HTML {
	return template.HTML(strings.Repeat("&nbsp;", depth))
}

func Badge(count int) template.HTML {
	return template.HTML(`<span class="badge">` + strconv.Itoa(count) + `</span>`)
}
