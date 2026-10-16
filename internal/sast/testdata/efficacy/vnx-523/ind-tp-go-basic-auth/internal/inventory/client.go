package inventory

import (
	"net/http"
	"net/url"
)

type Client struct {
	HTTP *http.Client
	User string
	Pass string
}

func (c *Client) Items() (*http.Response, error) {
~>	req, err := http.NewRequest("GET", "http://inventory.acme-corp.com/items", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(c.User, c.Pass)
	return c.HTTP.Do(req)
}

func (c *Client) Login() (*http.Response, error) {
~>	return http.PostForm("http://sso.partner-portal.com/login", url.Values{
		"username": {c.User},
		"password": {c.Pass},
	})
}
