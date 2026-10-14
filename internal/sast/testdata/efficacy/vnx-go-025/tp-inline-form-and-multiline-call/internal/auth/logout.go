package auth

import "net/http"

func Logout(w http.ResponseWriter, r *http.Request) {
	clearSession(w)
~>	http.Redirect(w, r, r.FormValue("return_to"), http.StatusSeeOther)
}

func Continue(w http.ResponseWriter, req *http.Request) {
	returnURL := req.PostFormValue("continue")
~>	http.Redirect(
		w, req,
		returnURL,
		http.StatusFound,
	)
}

func clearSession(w http.ResponseWriter) {}
