package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
)

func main() {
	adminMux := http.NewServeMux()
	go log.Fatal(http.ListenAndServe("127.0.0.1:9090", adminMux))
	go log.Fatal(http.ListenAndServe("localhost:9091", adminMux))
	go log.Fatal(http.ListenAndServeTLS(":9443", "cert.pem", "key.pem", adminMux))
	ln, err := net.Listen("tcp", cfg.AdminAddr)
	if err != nil {
		log.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, tlsConfig)
	http.Serve(tlsLn, adminMux)
	adminSrv := &http.Server{Addr: ":8443", Handler: adminMux, TLSConfig: tlsConfig}
	log.Fatal(adminSrv.ListenAndServeTLS("", ""))
	unixLn, _ := net.Listen("unix", "/run/app/admin.sock")
	http.Serve(unixLn, adminMux)
}
