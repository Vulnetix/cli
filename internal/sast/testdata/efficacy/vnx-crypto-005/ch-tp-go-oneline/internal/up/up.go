package up

import (
	"crypto/tls"
	"net/http"
)

var Client = &http.Client{
~>	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify:true}},
}
