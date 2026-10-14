package auth

import (
	"fmt"
	"net/http"
)

func LoginDone(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
~>	http.Redirect(w, r, next, http.StatusFound)
}

func Logout(w http.ResponseWriter, r *http.Request) {
~>	http.Redirect(w, r, r.FormValue("return_to"), http.StatusSeeOther)
}

func Continue(w http.ResponseWriter, r *http.Request) {
~>	http.Redirect(w, r,
		r.URL.Query().Get("continue"),
		http.StatusFound)
}

// A formatted destination that starts with the parameter is still the
// parameter's choice of host.
func Callback(w http.ResponseWriter, r *http.Request) {
	dest := fmt.Sprintf("%s?logged_in=1", r.FormValue("next"))
~>	http.Redirect(w, r, dest, http.StatusFound)
}

// A bare "/" prefix does not pin the host: next=/evil.example gives
// //evil.example, a scheme-relative URL.
func Home(w http.ResponseWriter, r *http.Request) {
	page := r.URL.Query().Get("page")
~>	http.Redirect(w, r, "/"+page, http.StatusFound)
}

func Tenant(w http.ResponseWriter, r *http.Request) {
~>	http.Redirect(w, r, "https://"+r.URL.Query().Get("host")+"/login", http.StatusFound)
}
