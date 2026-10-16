package inventory

import "net/http"

// Previously: http.NewRequest("GET", "http://inventory.acme-corp.com/items", nil) with SetBasicAuth.

func (c *Client) Items() (*http.Response, error) {
	req, err := http.NewRequest("GET", "https://inventory.acme-corp.com/items", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.User, c.Pass)
	return c.HTTP.Do(req)
}

func (c *Client) Health() (*http.Response, error) {
	req, err := http.NewRequest("GET", "http://status.acme-corp.com/healthz", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain")
	return c.HTTP.Do(req)
}

func (c *Client) Dev() (*http.Response, error) {
	req, _ := http.NewRequest("GET", "http://api.example.com/items", nil)
	req.SetBasicAuth(c.User, c.Pass)
	return c.HTTP.Do(req)
}

type Client struct {
	HTTP *http.Client
	User string
	Pass string
}
