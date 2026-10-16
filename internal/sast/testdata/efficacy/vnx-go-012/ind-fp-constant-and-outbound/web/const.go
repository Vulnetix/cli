package web

import "net/http"

func Proxy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	req, _ := http.NewRequest("GET", "https://upstream.example/api", nil)
	req.Header.Set("X-Trace", r.URL.Query().Get("trace"))
	http.DefaultClient.Do(req)
}
