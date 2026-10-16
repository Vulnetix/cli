package client

import (
	"encoding/base64"
	"net/http"
)

func setAuth(req *http.Request, user, password string) {
	creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
	req.Header.Set("Authorization", "Basic "+creds)
}
