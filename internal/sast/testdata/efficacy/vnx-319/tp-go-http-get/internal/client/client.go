package client

import "net/http"

func Status() (*http.Response, error) {
~>	return http.Get("http://status.cloud-vendor.io/health")
}

func Send(body io.Reader) {
~>	req, _ := http.NewRequest("POST", "http://ingest.cloud-vendor.io/v1", body)
	_ = req
}
