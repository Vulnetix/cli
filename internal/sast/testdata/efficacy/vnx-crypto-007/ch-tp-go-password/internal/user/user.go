package user

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

func Login(r *http.Request) string {
~>	pass := Md5Sum(r.FormValue("password"))
	return pass
}

func Store(password string, salt []byte) [32]byte {
~>	return sha256.Sum256([]byte(password + string(salt)))
}

func Store2(password string) string {
	h := md5.New()
~>	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

func Store3(pw []byte) ([]byte, error) {
~>	return bcrypt.GenerateFromPassword(pw, bcrypt.MinCost)
}

func Store4(password, salt []byte) []byte {
~>	return pbkdf2.Key(password, salt, 1000, 32, sha256.New)
}

func Md5Sum(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}
