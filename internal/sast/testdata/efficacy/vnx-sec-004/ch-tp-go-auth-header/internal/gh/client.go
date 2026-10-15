package gh

import "net/http"

func newRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
~>	req.Header.Set("Authorization", "token @@sample:ghs_[A-Za-z0-9]{36}@@")
	return req, nil
}
