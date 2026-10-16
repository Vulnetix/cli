package git

// Object is a git object as returned by the API.
type Object struct {
	SHA1 string `json:"sha1"`
	Size int64  `json:"size"`
}

// Same reports whether two objects have the same id.
func (o Object) Same(other Object) bool {
	return o.SHA1 == other.SHA1
}
