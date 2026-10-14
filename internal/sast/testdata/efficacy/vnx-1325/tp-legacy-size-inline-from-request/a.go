package a

func f(r *http.Request) []byte {
~>	return make([]byte, r.ContentLength)
}
