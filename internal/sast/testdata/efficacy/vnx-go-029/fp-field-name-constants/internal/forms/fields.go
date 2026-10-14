package forms

import "net/http"

const PasswordField = "password"

var fields = struct{ PasswordKey string }{PasswordKey: "password"}

func Read(r *http.Request) (string, string) {
	passwordParam := "password"
	labelPassword := "Password"
	_ = labelPassword
	return r.FormValue("username"), r.FormValue(passwordParam)
}

type Login struct {
	Password string `json:"password" yaml:"password"`
}
