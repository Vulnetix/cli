package main

import "net/http"

func main() {
	http.ListenAndServe(":8080", nil)
	srv := &http.Server{Addr: "127.0.0.1:6060"}
	srv.ListenAndServe()
}
