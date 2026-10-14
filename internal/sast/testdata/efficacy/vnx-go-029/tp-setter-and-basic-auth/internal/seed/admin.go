package seed

import (
	"net/http"
	"net/url"
)

func DefaultAdmin(u *User) {
	u.Name = "admin"
~>	u.SetPassword("admin")
}

func Probe(req *http.Request) {
~>	req.SetBasicAuth("monitor", "changeme")
}

func Upstream() *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   "registry.internal",
~>		User:   url.UserPassword("svc", "password123"),
	}
}

type User struct{ Name string }

func (u *User) SetPassword(string) {}
