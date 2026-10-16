package server

import "context"

type Client struct{}

func (c *Client) Login(ctx context.Context, user, pass string) error { return nil }

func Authenticated(token string) bool { return token != "" }
