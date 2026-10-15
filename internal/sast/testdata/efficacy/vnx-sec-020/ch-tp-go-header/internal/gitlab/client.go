package gitlab

import "net/http"

func newRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
~>	req.Header.Set("PRIVATE-TOKEN", "glpat-@@sample:[A-Za-z0-9]{20}@@")
	return req, nil
}
