package web

import "net/http"

type Client struct{ BaseURL string }

func (c *Client) Ping() (*http.Response, error) {
	return http.Get(c.BaseURL + "/ping")
}
