package upstream

import (
	"crypto/tls"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func NewClient() *http.Client {
	tr := &http.Transport{
~>		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func NewPinnedLooking(host string) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
~>		InsecureSkipVerify: true, //nolint:gosec // self-signed in staging
	}
}

func Dial(addr string) (*grpc.ClientConn, error) {
~>	creds := credentials.NewTLS(&tls.Config{ServerName: addr,InsecureSkipVerify:true})
	return grpc.Dial(addr, grpc.WithTransportCredentials(creds))
}
