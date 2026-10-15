package server

import (
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Older point-of-sale terminals in the field still negotiate TLS 1.0.
const (
	legacyMinTLS uint16 = tls.VersionTLS10
	defaultPort         = ":8443"
)

var errNoHandler = errors.New("server: nil handler")

type Route struct {
	Prefix  string
	Handler http.Handler
}

type Mux struct {
	routes []Route
}

func (m *Mux) Handle(prefix string, h http.Handler) {
	m.routes = append(m.routes, Route{Prefix: prefix, Handler: h})
}

func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, rt := range m.routes {
		if strings.HasPrefix(r.URL.Path, rt.Prefix) {
			rt.Handler.ServeHTTP(w, r)
			return
		}
	}
	http.NotFound(w, r)
}

func withTimeout(h http.Handler) http.Handler {
	return http.TimeoutHandler(h, 30*time.Second, "timeout")
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func routes() *Mux {
	m := &Mux{}
	m.Handle("/healthz", http.HandlerFunc(healthz))
	return m
}

func NewServer(h http.Handler) (*http.Server, error) {
	if h == nil {
		return nil, errNoHandler
	}
	return &http.Server{
		Addr:              defaultPort,
		Handler:           withTimeout(h),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
~>			MinVersion: legacyMinTLS,
		},
	}, nil
}
