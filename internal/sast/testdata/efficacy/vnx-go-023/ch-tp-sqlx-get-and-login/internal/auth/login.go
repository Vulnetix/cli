package auth

import (
	"net/http"

	"github.com/jmoiron/sqlx"
)

type User struct {
	ID    int64  `db:"id"`
	Email string `db:"email"`
}

func Login(db *sqlx.DB, w http.ResponseWriter, r *http.Request) {
	email := r.PostFormValue("email")
	pass := r.PostFormValue("password")
	var u User
~>	err := db.Get(&u, "SELECT id, email FROM users WHERE email = '"+email+"' AND password = '"+pass+"'")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
	}
}
