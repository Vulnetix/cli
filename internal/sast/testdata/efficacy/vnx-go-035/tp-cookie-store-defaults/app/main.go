package main

import "github.com/gorilla/sessions"

~>var store = sessions.NewCookieStore([]byte("hash-key-from-env-in-prod"))

func main() {
	serve(store)
}
