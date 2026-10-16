package main

import (
	"fmt"
	"net/http"
)

func call(host, secret string) (*http.Response, error) {
~>	u := fmt.Sprintf("https://%s/v1/data?client_secret=%s", host, secret)
	return http.Get(u)
}
