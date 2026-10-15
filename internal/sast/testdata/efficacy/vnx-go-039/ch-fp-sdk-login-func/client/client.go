package client

import (
	"context"
	"net/http"
	"net/url"
)

type Credentials struct {
	User, Password string
}

// Login exchanges credentials for a session token with the remote API.
func Login(ctx context.Context, hc *http.Client, base string, creds Credentials) (string, error) {
	form := url.Values{"user": {creds.User}, "password": {creds.Password}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/login", nil)
	if err != nil {
		return "", err
	}
	req.URL.RawQuery = form.Encode()
	res, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	return res.Header.Get("X-Session"), nil
}

func SignIn(ctx context.Context, creds Credentials) error {
	_, err := Login(ctx, http.DefaultClient, "https://api.example.com", creds)
	return err
}
