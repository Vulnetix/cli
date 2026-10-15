package client

import "net/http"

func Authorize(req *http.Request) {
~>	req.SetBasicAuth("admin", "admin")
}
