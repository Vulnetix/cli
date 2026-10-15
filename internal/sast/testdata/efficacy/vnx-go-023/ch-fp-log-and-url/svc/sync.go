package svc

import (
	"log"
	"net/http"
)

func Sync(base, name string) (*http.Response, error) {
	log.Println("UPDATE users SET name = '" + name + "' failed, retrying")
	return http.Get(base + "/api/users?filter=name='" + name + "'")
}
