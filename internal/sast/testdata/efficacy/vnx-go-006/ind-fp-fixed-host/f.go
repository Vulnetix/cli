package web

import "net/http"

func Status() (*http.Response, error) {
	return http.Get("https://api.example.com/health")
}
