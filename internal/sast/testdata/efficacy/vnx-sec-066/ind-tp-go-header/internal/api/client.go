package api

import "net/http"

func newReq(url string) (*http.Request, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
~>	req.Header.Set("Authorization", "Bearer @@sample:[A-Za-z0-9]{36}@@")
	return req, nil
}
