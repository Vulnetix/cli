package a

func f(r *http.Request) {
	count, _ := strconv.Atoi(r.FormValue("n"))
	for i := 0; i < count; i++ {
~>		buf := make([]byte, 1024)
		process(buf)
	}
	tail := make([]byte, 1024)
}
