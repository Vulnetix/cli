package client

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
)

// Cookies a client sends to a server: Secure is a server-to-browser attribute.
func Call(token string) (*http.Response, error) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/me", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: token})
	return http.DefaultClient.Do(req)
}

func Seed(u *url.URL, token string) http.CookieJar {
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(u, []*http.Cookie{{Name: "sid", Value: token}})
	return jar
}

func toSend(entries map[string]string) []*http.Cookie {
	var cookies []*http.Cookie
	for k, v := range entries {
		cookies = append(cookies, &http.Cookie{Name: k, Value: v})
	}
	return cookies
}
