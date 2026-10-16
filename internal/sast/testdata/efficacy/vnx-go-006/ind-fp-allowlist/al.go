package web

import (
	"net/http"
)

var allowed = map[string]string{"a": "https://a.example.com", "b": "https://b.example.com"}

func Pick(w http.ResponseWriter, r *http.Request) {
	dst, ok := allowed[r.URL.Query().Get("svc")]
	if !ok {
		http.Error(w, "no", 400)
		return
	}
	http.Get(dst)
}
