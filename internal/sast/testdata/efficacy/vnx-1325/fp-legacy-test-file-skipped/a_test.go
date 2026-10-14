package a

func f(r *http.Request) []byte {
	n, _ := strconv.Atoi(r.Header.Get("X-Size"))
	return make([]byte, n)
}
