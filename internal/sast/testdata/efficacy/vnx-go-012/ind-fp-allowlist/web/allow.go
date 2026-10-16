package web

import "net/http"

var langs = map[string]bool{"en": true, "fr": true}

func Localised(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	if !langs[lang] {
		lang = "en"
	}
	w.Header().Set("Content-Language", lang)
}
