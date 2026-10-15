package web

import "net/http"

func startSession(w http.ResponseWriter, id string) {
~>	w.Header().Add("Set-Cookie", "session="+id+"; Path=/; HttpOnly; SameSite=Lax")
}

func remember(w http.ResponseWriter, tok string) {
~>	w.Header().Set("Set-Cookie", fmt.Sprintf("remember=%s; Max-Age=2592000; HttpOnly", tok))
}
