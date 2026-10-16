package web

import "html/template"

func Banner() map[string]any {
	return map[string]any{
		"Banner": template.HTML(`<span class="beta">Beta</span>`),
		"Logo":   template.HTML("<img src=\"/static/logo.svg\" alt=\"logo\">"),
	}
}
