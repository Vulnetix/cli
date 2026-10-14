package web

import (
	"net/http"
	"net/url"
	"strconv"
)

var supported = map[string]bool{"en": true, "fr": true, "de": true}

func List(w http.ResponseWriter, r *http.Request) {
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil {
		page = 1
	}
	w.Header().Set("X-Page", strconv.Itoa(page))

	q := r.URL.Query().Get("q")
	w.Header().Set("Link", "</search?q="+url.QueryEscape(q)+"&page=2>; rel=\"next\"")

	lang := r.URL.Query().Get("lang")
	if !supported[lang] {
		lang = "en"
	}
	w.Header().Set("Content-Language", lang)
}
