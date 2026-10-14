package a

func h(w http.ResponseWriter, r *http.Request) {
	var user User
~>	_ = json.NewDecoder(r.Body).Decode(&user)
	db.Save(&user)
}
