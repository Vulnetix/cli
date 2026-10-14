package a

func f(r *http.Request) {
	u := "https://example.com/a/b"
	auth := r.Header.Get("Authorization")
	_ = u + auth
}
