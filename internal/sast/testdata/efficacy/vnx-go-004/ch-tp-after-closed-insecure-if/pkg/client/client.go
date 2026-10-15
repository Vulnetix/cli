package client

import (
	"crypto/tls"
	"log"
	"net/http"
)

func New(insecure bool) *http.Client {
	if insecure {
		log.Println("warning: --insecure given")
	}
~>	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return &http.Client{Transport: tr}
}
