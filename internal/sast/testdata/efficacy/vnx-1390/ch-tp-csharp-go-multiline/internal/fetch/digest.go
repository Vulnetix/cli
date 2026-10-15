package fetch

import (
	"net/http"

	"github.com/icholy/digest"
)

func Client(user, pass string) *http.Client {
	return &http.Client{
~>		Transport: &digest.Transport{
			Username: user,
			Password: pass,
		},
	}
}
