package api

import "net/http"

func authorise(req *http.Request) {
~>	req.Header.Set("Authorization", "Bearer @@sample:eyJ[A-Za-z0-9_-]{30}\.eyJ[A-Za-z0-9_-]{40}\.[A-Za-z0-9_-]{43}@@")
}
