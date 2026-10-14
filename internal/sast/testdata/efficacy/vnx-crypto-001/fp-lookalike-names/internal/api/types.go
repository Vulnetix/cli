package api

import "net/http"

// Artifact describes an uploaded object; MD5 is the value the registry
// reports, not something this service computes.
type Artifact struct {
	Name   string `json:"name"`
	MD5    string `json:"md5"`
	SHA256 string `json:"sha256"`
}

func contentMD5(r *http.Response) string {
	md5sum := r.Header.Get("Content-MD5")
	return md5sum
}
