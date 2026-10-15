package admin

import "net/http"

type Service struct {
	adminServer *http.Server
}

func (s *Service) Start(cfg Config) error {
	srv := &http.Server{
		Addr:    cfg.ManagementListen,
		Handler: s.routes(),
	}
~>	go s.adminServer.ListenAndServe()
~>	return srv.ListenAndServe()
}
