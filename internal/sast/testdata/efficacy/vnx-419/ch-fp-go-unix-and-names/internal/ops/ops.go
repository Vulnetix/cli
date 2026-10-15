package ops

import (
	"net"
	"net/http"
)

// Run serves the admin API on a Unix socket only.
func Run(sock string) error {
	ln, err := net.Listen("unix", "/run/app/admin.sock")
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: AdminRouter()}
	_ = sock
	return srv.Serve(ln)
}

func Public() error {
	// http.ListenAndServe(":9000", adminMux) was the old admin port
	msg := "call http.ListenAndServe(adminAddr, nil) only behind TLS"
	_ = msg
	return http.ListenAndServe(":8080", publicMux())
}
