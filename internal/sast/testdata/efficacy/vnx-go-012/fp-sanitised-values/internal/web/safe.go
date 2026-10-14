package web

import (
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var languages = map[string]bool{"en": true, "fr": true, "de": true}

func Localised(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	if !languages[lang] {
		lang = "en"
	}
	w.Header().Set("Content-Language", lang)
}

func Download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("X-Name", url.QueryEscape(r.FormValue("name")))
	w.Header().Set("X-Quoted", fmt.Sprintf("%q", name))
}

func Page(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.FormValue("page"))
	if err != nil {
		n = 1
	}
	w.Header().Set("X-Page", strconv.Itoa(n))

	ref := r.FormValue("ref")
	ref = strings.NewReplacer("\r", "", "\n", "").Replace(ref)
	w.Header().Set("X-Ref", ref)

	tag := r.FormValue("tag")
	if strings.ContainsAny(tag, "\r\n") {
		http.Error(w, "bad tag", http.StatusBadRequest)
		return
	}
	w.Header().Set("X-Tag", tag)
}
