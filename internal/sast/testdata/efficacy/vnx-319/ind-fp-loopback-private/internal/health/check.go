package health

import "net/http"

func Local() (*http.Response, error) {
	return http.Get("http://localhost:8080/healthz")
}

func Sidecar() (*http.Response, error) {
	return http.Get("http://10.0.12.7:9000/ready")
}
