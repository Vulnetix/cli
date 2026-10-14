package handlers

import "net/http"

// Back to the page the browser came from; a victim's browser chooses its own
// Referer, the attacker cannot.
func Back(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
}

func Canonical(w http.ResponseWriter, r *http.Request) {
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "http" {
		http.Redirect(w, r, "https://"+r.Host+r.URL.Path, http.StatusPermanentRedirect)
	}
}

// The redirect target is a fixed route; the parameter only picks the tab.
func Tabs(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	http.Redirect(w, r, "/settings?tab="+url.QueryEscape(tab), http.StatusFound)
}
