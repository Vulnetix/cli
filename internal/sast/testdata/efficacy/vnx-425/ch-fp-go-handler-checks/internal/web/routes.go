package web

import "net/http"

func Register(mux *http.ServeMux) {
	mux.HandleFunc("/admin/flush", flushCache)
	mux.HandleFunc("/admin/export", func(w http.ResponseWriter, r *http.Request) {
		u, ok := userFromContext(r.Context())
		if !ok || !u.IsAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		export(w)
	})
}

func flushCache(w http.ResponseWriter, r *http.Request) {
	if !hasRole(r, "admin") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	cache.Flush()
}
