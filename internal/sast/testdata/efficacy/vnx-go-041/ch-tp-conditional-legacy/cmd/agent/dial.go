package main

import (
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func dialCollector(addr string, legacy bool) (*grpc.ClientConn, error) {
	cfg := &tls.Config{ServerName: "collector.internal"}
	if legacy {
~>		cfg.MinVersion = tls.VersionTLS10
	}
	return grpc.Dial(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
}

func dialMetrics(addr string) (*grpc.ClientConn, error) {
~>	creds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS11})
	return grpc.Dial(addr, grpc.WithTransportCredentials(creds))
}
