package preview

import (
	"net/http"
	"net/url"
)

var allowedHosts = map[string]bool{"images.example.com": true, "cdn.example.net": true}

func Fetch(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("src")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !allowedHosts[u.Hostname()] {
		http.Error(w, "source not allowed", http.StatusBadRequest)
		return
	}
	resp, err := http.Get(u.String())
	if err != nil {
		http.Error(w, "fetch", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
}
