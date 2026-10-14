package web

// Never do http.Redirect(w, r, r.FormValue("redirect_uri"), 302).
const warning = `http.Redirect(w, r, r.FormValue("redirect_uri"), 302) is an open redirect`
