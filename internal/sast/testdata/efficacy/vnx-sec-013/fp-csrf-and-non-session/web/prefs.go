package web

func setTheme(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:  "theme",
		Value: "dark",
		Path:  "/",
	})
}
