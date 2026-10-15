package client

import (
	"net/http"
	"net/url"
)

func Fetch(user, pass string) (*http.Response, error) {
~>	req, err := http.NewRequest("GET", "http://inventory.acme-corp.com/items", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(user, pass)
	return http.DefaultClient.Do(req)
}

func Login(username, password string) (*http.Response, error) {
~>	return http.PostForm("http://auth.acme-corp.com/login", url.Values{"username": {username}, "password": {password}})
}
