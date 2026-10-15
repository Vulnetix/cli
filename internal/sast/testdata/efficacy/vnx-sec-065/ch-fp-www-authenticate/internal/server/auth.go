package server

import (
	"encoding/base64"
	"net/http"
)

func challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
	w.WriteHeader(http.StatusUnauthorized)
}

func authHeader(user, pass string) string {
	return "Basic " + @@sample:b[a]se[6]4[.][S]td[E]nc[o]di[n]g[.][E]nc[o]de[T]oS[t]ri[n]g@@([]byte(user+":"+pass))
}
