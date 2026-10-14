package server

import (
	"net/http"
	"sync"
)

~>type Server struct {
	cfg           *Config
	router        *Router
	db            *sql.DB
	cache         Cache
	sessions      map[string]*Session
	limiter       *rate.Limiter
	metrics       *Metrics
	inbound, outbound chan *Message
	handlers      []http.Handler
	mu            sync.Mutex
	*Logger
	name    string
	port    int
	verbose bool
}

type Option func(*Server)
