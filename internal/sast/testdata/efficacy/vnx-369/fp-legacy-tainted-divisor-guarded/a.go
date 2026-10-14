package a

func f(r *http.Request, total int) int {
	n, _ := strconv.Atoi(r.FormValue("n"))
	if n == 0 {
		return 0
	}
	return total / n
}
