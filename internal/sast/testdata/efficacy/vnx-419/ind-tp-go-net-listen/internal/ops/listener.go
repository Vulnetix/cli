package ops

import (
	"net"
	"net/http"
)

func ServeAdmin(adminAddr string, h http.Handler) error {
~>	ln, err := net.Listen("tcp", adminAddr)
	if err != nil {
		return err
	}
	return http.Serve(ln, h)
}
