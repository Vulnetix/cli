package api

import "net/http"

func Call(url, apiKey string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url+"?page=1", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", apiKey)
	return http.DefaultClient.Do(req)
}
