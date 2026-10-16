package oauth

import (
	"net/http"

	"golang.org/x/oauth2"
)

var conf = &oauth2.Config{
	ClientID:    "web",
	RedirectURL: "https://app.example.com/callback",
}

func start(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, conf.AuthCodeURL("state"), http.StatusFound)
}

func home(w http.ResponseWriter, r *http.Request) {
	// redirect_uri must come from the registered client, never r.FormValue("redirect_uri")
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
