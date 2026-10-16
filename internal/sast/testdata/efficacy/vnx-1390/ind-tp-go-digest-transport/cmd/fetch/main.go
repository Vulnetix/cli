package main

import (
	"net/http"

	"github.com/icholy/digest"
)

func client(u, p string) *http.Client {
~>	return &http.Client{Transport: &digest.Transport{Username: u, Password: p}}
}
