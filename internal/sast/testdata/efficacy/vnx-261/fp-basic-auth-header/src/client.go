package client

import (
	"encoding/base64"
	"net/http"
)

func basic(req *http.Request, user, password string) {
	creds := user + ":" + password
	req.Header.Set("Authorization", "Basic "+@@sample:b[a]se[6]4[.][S]td[E]nc[o]di[n]g[.][E]nc[o]de[T]oS[t]ri[n]g@@([]byte(creds)))
}
