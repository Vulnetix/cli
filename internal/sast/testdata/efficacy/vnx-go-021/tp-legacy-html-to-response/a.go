package main

func h(w http.ResponseWriter, r *http.Request) {
~>	fmt.Fprintf(w, "<h1>Hello %s</h1>", r.FormValue("name"))
}
