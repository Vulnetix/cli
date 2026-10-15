package billing

import "net/http"

~>const adminKey = "sk-ant-admin01-@@sample:[A-Za-z0-9_-]{93}@@AA"

func newRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", adminKey)
	return req, nil
}
