package main

import (
	"log"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
)

// An ordinary service bound to every interface is how a container serves;
// nothing internal is mounted on it. The general binding question is
// VNX-1327's, not this rule's.
func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders", orders)
	go http.ListenAndServe(":8080", mux)
	go http.ListenAndServe("0.0.0.0:8443", nil)
	ln, err := net.Listen("tcp", ":9000")
	if err != nil {
		log.Fatal(err)
	}
	go http.Serve(ln, mux)
	r := gin.Default()
	r.Run(":3000")
}

func orders(w http.ResponseWriter, r *http.Request) {}
