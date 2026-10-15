package user

func register(r *http.Request) {
	hashed, _ := bcrypt.GenerateFromPassword([]byte(r.FormValue("password")), 12)
	u.Password = string(hashed)
}
