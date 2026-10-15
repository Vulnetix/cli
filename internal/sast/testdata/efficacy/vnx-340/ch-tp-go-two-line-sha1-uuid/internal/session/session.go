package session

import (
	"net/http"

	"github.com/google/uuid"
)

var ns = uuid.MustParse("@@sample:6[b]a7[b]81[0][-]9[d]ad[-]11[d]1[-][8]0b[4][-]0[0]c0[4]fd[4]30[c]8@@")

func Start(w http.ResponseWriter, user string) {
~>	id := uuid.NewSHA1(ns, []byte(user)).String()
	http.SetCookie(w, &http.Cookie{Name: "session_id", Value: id, HttpOnly: true})
}
