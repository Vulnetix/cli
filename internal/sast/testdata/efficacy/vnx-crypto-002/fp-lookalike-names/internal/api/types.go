package api

// Release mirrors the upstream metadata, which still publishes SHA1.
type Release struct {
	Version string `json:"version"`
	SHA1    string `json:"sha1"`
	SHA256  string `json:"sha256"`
}

func (r Release) HasSHA1() bool { return r.SHA1 != "" }
