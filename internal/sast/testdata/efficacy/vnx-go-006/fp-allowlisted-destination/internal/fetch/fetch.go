package fetch

import (
	"io"
	"net/http"
	"net/url"
)

var allowedHosts = map[string]bool{"images.example.com": true, "cdn.example.com": true}

func Image(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("src")
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || !allowedHosts[u.Hostname()] {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, "upstream", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func Avatar(w http.ResponseWriter, r *http.Request) {
	src := r.URL.Query().Get("src")
	if err := validateOutboundURL(src); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	resp, err := http.Get(src)
	if err == nil {
		resp.Body.Close()
	}
}

func validateOutboundURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if !allowedHosts[u.Hostname()] {
		return http.ErrNotSupported
	}
	return nil
}
