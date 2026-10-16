package oauth

import (
	"net/http"
	"os"
)

// Client talks to the identity provider.
//
~>// refresh_token = "rt-55091-ab72-staging"
type Client struct {
	HTTP   *http.Client
	ID     string
	Secret string
}

func New() *Client {
	return &Client{
		HTTP:   http.DefaultClient,
		ID:     os.Getenv("OAUTH_CLIENT_ID"),
~>		Secret: os.Getenv("OAUTH_CLIENT_SECRET"), // secret: Kx8#pq2Lm9
	}
}
