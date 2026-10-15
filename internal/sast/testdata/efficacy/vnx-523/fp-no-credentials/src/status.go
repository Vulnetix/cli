package src

import "net/http"

func Status() (*http.Response, error) {
	req, _ := http.NewRequest("GET", "http://status.acme-corp.com/health", nil)
	req.Header.Set("Accept", "application/json")
	return http.DefaultClient.Do(req)
}

func Secure(user, pass string) (*http.Response, error) {
	req, _ := http.NewRequest("GET", "https://inventory.acme-corp.com/items", nil)
	req.SetBasicAuth(user, pass)
	return http.DefaultClient.Do(req)
}
