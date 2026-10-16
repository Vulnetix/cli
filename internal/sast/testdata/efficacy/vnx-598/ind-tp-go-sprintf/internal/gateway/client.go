package gateway

import (
	"fmt"
	"net/http"
	"time"
)

type Client struct {
	Base string
	HTTP *http.Client
}

func New(base string) *Client {
	return &Client{Base: base, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) Authenticate(user, pwd string) (*http.Response, error) {
~>	u := fmt.Sprintf("%s/auth?user=%s&pwd=%s", c.Base, user, pwd)
	return c.HTTP.Get(u)
}
