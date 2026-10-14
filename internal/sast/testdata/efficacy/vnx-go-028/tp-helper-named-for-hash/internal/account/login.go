package account

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
)

func Login(w http.ResponseWriter, r *http.Request) {
	uname := r.FormValue("username")
~>	pass := Md5Sum(r.FormValue("password"))
	check(uname, pass)
}

func Register(req RegisterRequest) {
~>	hashed := util.SHA1Hex(req.Password)
	save(req.Email, hashed)
}

func Md5Sum(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

type RegisterRequest struct{ Email, Password string }

func check(string, string) {}
func save(string, string)  {}
