package a

func h(w http.ResponseWriter, r *http.Request) {
~>	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.WriteHeader(201)
}
