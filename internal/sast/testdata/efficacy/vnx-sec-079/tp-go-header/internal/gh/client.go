package gh

import "net/http"

func auth(r *http.Request) {
~>	r.Header.Set("Authorization", "Bearer github_pat_@@sample:[A-Za-z0-9]{22}@@_@@sample:[A-Za-z0-9]{59}@@")
}
