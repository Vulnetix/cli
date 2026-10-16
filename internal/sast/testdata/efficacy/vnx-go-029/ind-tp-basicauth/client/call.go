package client

import "net/http"

func Call() (*http.Response, error) {
	req, _ := http.NewRequest("GET", "https://svc.internal/api", nil)
~>	req.SetBasicAuth("admin", "admin")
	return http.DefaultClient.Do(req)
}
