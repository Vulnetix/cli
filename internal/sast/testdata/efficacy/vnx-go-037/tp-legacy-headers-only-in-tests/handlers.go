package a

func h(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
~>	_ = page.Execute(w, data)
}
