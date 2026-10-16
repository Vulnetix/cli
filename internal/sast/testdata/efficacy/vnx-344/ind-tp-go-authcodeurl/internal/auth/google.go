package auth

import (
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var conf = &oauth2.Config{
	ClientID:     "client-id",
	ClientSecret: "client-secret",
	RedirectURL:  "https://app.example.com/oauth/callback",
	Scopes:       []string{"openid", "email"},
	Endpoint:     google.Endpoint,
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
~>	url := conf.AuthCodeURL("login-state", oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusFound)
}
