package auth

import (
	"net/http"
	"net/url"
	"strconv"
)

func Links(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, err := strconv.Atoi(q.Get("page"))
	if err != nil {
		page = 1
	}
	w.Header().Set("X-Page", strconv.Itoa(page))
	w.Header().Set("Link", "</items?cursor="+url.QueryEscape(q.Get("cursor"))+">; rel=\"next\"")
	w.Header().Set("X-Count", strconv.Itoa(len(q)))
}
