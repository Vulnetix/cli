package user

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
~>	_, err := h.db.Exec("INSERT INTO users(name, password) VALUES($1, $2)", name, r.FormValue("password"))
	if err != nil {
		return
	}
	var u User
~>	u.Password = r.PostFormValue("password")
	h.orm.Create(&u)
}
