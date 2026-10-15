package notion

import "net/http"

func newRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
~>	req.Header.Set("Authorization", "Bearer ntn_@@sample:[0-9]{11}@@@@sample:[A-Za-z0-9]{35}@@")
	req.Header.Set("Notion-Version", "2022-06-28")
	return req, nil
}
