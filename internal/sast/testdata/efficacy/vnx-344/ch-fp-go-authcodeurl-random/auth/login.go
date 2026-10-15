package auth

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"golang.org/x/oauth2"
)

var conf = &oauth2.Config{ClientID: "client"}

func newState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return @@sample:b[a]se[6]4[.][R]aw[U]RL[E]nc[o]di[n]g[.][E]nc[o]de[T]oS[t]ri[n]g@@(b)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state := newState()
	http.SetCookie(w, &http.Cookie{Name: "oauthstate", Value: state, HttpOnly: true})
	url := conf.AuthCodeURL(state, @@sample:o[a]ut[h]2[.][A]cc[e]ss[T]yp[e]Of[f]li[n]e@@)
	// conf.AuthCodeURL("state") is what the docs example shows; never ship it
	http.Redirect(w, r, url, http.StatusFound)
}
