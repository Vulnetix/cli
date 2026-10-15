package edge

import "net/http"

const loginPage = "/login"

func ForceHTTPS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
}

func RequireLogin(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("session") == "" {
		w.Header().Set("Location", loginPage)
		w.WriteHeader(http.StatusFound)
		return
	}
	http.Redirect(w, r, "/dashboard?tab="+r.URL.Query().Get("tab"), http.StatusFound)
}
