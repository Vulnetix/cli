package web

import "net/http"

// Never do w.Header().Set("X-Theme", r.URL.Query().Get("theme")) directly.
func Theme(w http.ResponseWriter, r *http.Request) {
	theme := r.URL.Query().Get("theme")
	switch theme {
	case "dark", "light":
	default:
		theme = "light"
	}
	w.Header().Set("X-Theme", theme)
	msg := `w.Header().Set("X-Theme", r.URL.Query().Get("theme"))`
	_ = msg
}
