package a

func h(w http.ResponseWriter, r *http.Request) {
	p := r.FormValue("p")
~>	target, err := os.Readlink(p)
}
