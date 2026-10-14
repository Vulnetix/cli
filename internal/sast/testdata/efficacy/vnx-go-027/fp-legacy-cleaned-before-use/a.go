package a

func h(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.FormValue("file"))
	data, _ := os.ReadFile(filepath.Join(base, name))
}
