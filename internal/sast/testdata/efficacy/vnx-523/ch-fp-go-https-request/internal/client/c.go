package client

import "net/http"

func Get(token string) (*http.Response, error) {
	req, err := http.NewRequest("GET", "https://api.vendorhub.io/data", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	pub, _ := http.NewRequest("GET", "http://mirror.vendorhub.io/index", nil)
	_ = pub
	return http.DefaultClient.Do(req)
}
