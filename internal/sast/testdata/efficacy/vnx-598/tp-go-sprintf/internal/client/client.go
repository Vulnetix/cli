package client

import (
	"fmt"
	"net/http"
)

func Get(base, token string) (*http.Response, error) {
~>	u := fmt.Sprintf("%s/api/data?token=%s", base, token)
	return http.Get(u)
}

func Login(base, user, pw string) (*http.Response, error) {
~>	return http.Get(base + "/login?user=" + user + "&passwd=" + pw)
}
