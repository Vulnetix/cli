package a

func h(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
~>	out, _ := exec.Command("ping", host).Output()
}
