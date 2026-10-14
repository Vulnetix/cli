package a

func h(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	name = validate.Name(name)
	os.Open(name)
}
