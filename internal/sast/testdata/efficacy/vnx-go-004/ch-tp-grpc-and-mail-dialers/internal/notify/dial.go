package notify

import (
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/gomail.v2"
)

func Conn(addr string) (*grpc.ClientConn, error) {
~>	return grpc.Dial(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
}

func Mailer(host string, port int, user, pass string) *gomail.Dialer {
	d := gomail.NewDialer(host, port, user, pass)
	d.TLSConfig = &tls.Config{
		ServerName:         host,
~>		InsecureSkipVerify:true,
	}
	return d
}
