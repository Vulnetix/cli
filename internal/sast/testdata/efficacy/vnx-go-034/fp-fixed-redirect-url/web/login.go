package web

import (
	"net/http"

	"golang.org/x/oauth2"
)

var conf = &oauth2.Config{
	ClientID:    clientID,
	RedirectURL: "https://app.example.com/oauth/callback",
}

func login(w http.ResponseWriter, r *http.Request) {
	cfg := *conf
	cfg.RedirectURL = settings.CallbackURL
	state := r.URL.Query().Get("state")
	http.Redirect(w, r, cfg.AuthCodeURL(state), http.StatusFound)
}
