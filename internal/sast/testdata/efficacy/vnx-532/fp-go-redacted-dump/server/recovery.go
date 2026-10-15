package server

import (
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
)

func Recover(r *http.Request) {
	dump, _ := httputil.DumpRequest(r, false)
	headers := strings.Split(string(dump), "\r\n")
	for i, h := range headers {
		if strings.HasPrefix(h, "Authorization:") {
			headers[i] = "Authorization: *"
		}
	}
	log.Println(strings.Join(headers, "\r\n"))
	log.Printf("ua=%s", r.Header.Get("User-Agent"))
}
