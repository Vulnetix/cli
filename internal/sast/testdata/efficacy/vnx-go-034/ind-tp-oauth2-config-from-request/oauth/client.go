package oauth

import (
	"net/http"

	"golang.org/x/oauth2"
)

func login(w http.ResponseWriter, r *http.Request, base oauth2.Endpoint) {
	conf := &oauth2.Config{
		ClientID: "web",
		Endpoint: base,
~>		RedirectURL: r.FormValue("redirect_uri"),
	}
	http.Redirect(w, r, conf.AuthCodeURL("st"), http.StatusFound)
}
