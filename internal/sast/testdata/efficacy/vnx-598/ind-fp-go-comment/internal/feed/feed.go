package feed

import (
	"net/http"
	"net/url"
)

// The old endpoint was /feed?token=<value>; the token now travels in a header.
func Fetch(base, token string) (*http.Response, error) {
	u, err := url.Parse(base + "/feed")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultClient.Do(req)
}
