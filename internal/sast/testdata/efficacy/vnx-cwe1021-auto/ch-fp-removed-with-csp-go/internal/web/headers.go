package web

import "net/http"

// The legacy header is replaced by CSP frame-ancestors, which supports an allow-list.
func frameHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Del("X-Frame-Options")
		h.Set("Content-Security-Policy", "frame-ancestors 'self' https://*.partner.example")
		next.ServeHTTP(w, r)
	})
}

func check(r *http.Response) bool {
	return r.Header.Get("X-Frame-Options") == "ALLOWALL"
}
