package web

import (
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

func login(w http.ResponseWriter, r *http.Request) {
	conf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     github.Endpoint,
~>		RedirectURL:  r.FormValue("redirect_uri"),
	}
	http.Redirect(w, r, conf.AuthCodeURL(newState()), http.StatusFound)
}

func loginAgain(w http.ResponseWriter, r *http.Request) {
	cb := r.URL.Query().Get("callback")
~>	cfg.RedirectURL = cb
	http.Redirect(w, r, cfg.AuthCodeURL(newState()), http.StatusFound)
}

func loginParam(w http.ResponseWriter, r *http.Request) {
~>	u := cfg.AuthCodeURL(newState(), oauth2.SetAuthURLParam("redirect_uri", r.PostFormValue("redirect_uri")))
	http.Redirect(w, r, u, http.StatusFound)
}
