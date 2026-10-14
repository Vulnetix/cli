package a

func f(r *http.Request, total int) int {
	n, _ := strconv.Atoi(r.FormValue("n"))
~>	return total / n
}
