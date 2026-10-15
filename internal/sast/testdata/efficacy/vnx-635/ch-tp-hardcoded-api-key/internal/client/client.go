package client

import "net/http"

~>// TODO(jdoe): remove hardcoded API key and read it from the environment
const apiKey = "replace-me"

func New() *http.Client {
	return &http.Client{}
}
