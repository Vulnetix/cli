package gh

import "net/http"

func authorize(req *http.Request) {
~>	req.Header.Set("Authorization", "Bearer github_pat_@@sample:[A-Za-z0-9]{22}_[A-Za-z0-9]{59}@@")
}
