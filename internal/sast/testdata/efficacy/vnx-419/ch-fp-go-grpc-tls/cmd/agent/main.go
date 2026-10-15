package main

import (
	"crypto/tls"
	"net"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func serve(cfg Config) error {
	creds := credentials.NewTLS(&tls.Config{Certificates: cfg.Certs})
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	lis, err := net.Listen("tcp", cfg.ManagementAddr)
	if err != nil {
		return err
	}
	go grpcServer.Serve(lis)
	adminSrv := &http.Server{Addr: cfg.AdminAddr, Handler: adminMux()}
	return adminSrv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
}
