package server

import (
	"net/http"
	"sync"
)

~>type Server struct {
	mu        sync.Mutex
	name      string
	cfg       *Config
	log       *Logger
	sessions  map[string]*Session
	users     *UserStore
	orders    *OrderStore
	mailer    *Mailer
	cache     *Cache
	router    *Router
	metrics   *Metrics
	tracer    *Tracer
	handler   http.Handler
	queue     chan *Job
}
