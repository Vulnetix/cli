package auth

import (
	"net/http"

	"golang.org/x/oauth2"
)

var googleConf = &oauth2.Config{
	ClientID:     "client",
	ClientSecret: "",
	RedirectURL:  "https://app.example.com/callback",
	Endpoint:     oauth2.Endpoint{AuthURL: "https://accounts.example.com/o/oauth2/auth"},
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
~>	url := googleConf.AuthCodeURL("random-state-string", @@sample:o[a]ut[h]2[.][A]cc[e]ss[T]yp[e]Of[f]li[n]e@@)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}
