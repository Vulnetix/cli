package auth

// func Login(w http.ResponseWriter, r *http.Request) is served by the IdP.
const example = `func SignIn(c *gin.Context) {}`

func LoginURL(base string) string { return base + "/login" }

func (c *Client) Login(ctx context.Context, user, pass string) error { return nil }
