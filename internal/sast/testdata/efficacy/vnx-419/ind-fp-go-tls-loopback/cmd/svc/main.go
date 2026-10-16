package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
)

func main() {
	adminMux := http.NewServeMux()
	go log.Fatal(http.ListenAndServeTLS(":9443", "admin.crt", "admin.key", adminMux))
	go log.Fatal(http.ListenAndServe("127.0.0.1:9090", adminMux))
	go log.Fatal(http.ListenAndServe("localhost:9091", adminMux))

	adminAddr := "127.0.0.1:9100"
	go http.ListenAndServe(adminAddr, adminMux)

	ln, err := net.Listen("tcp", ":9200")
	if err != nil {
		log.Fatal(err)
	}
	adminLn := tls.NewListener(ln, tlsConfig())
	go http.Serve(adminLn, adminMux)

	ctl, _ := net.Listen("unix", "/run/svc/admin.sock")
	go http.Serve(ctl, adminMux)

	apiMux := http.NewServeMux()
	// http.ListenAndServe(":9090", adminMux) for local debugging only
	log.Fatal(http.ListenAndServe(":8080", apiMux))
}
