package gh

import (
	"fmt"
	"net/http"
)

func Repos(base, accessToken string) (*http.Response, error) {
~>	u := fmt.Sprintf("%s/user/repos?access_token=%s", base, accessToken)
	return http.Get(u)
}
