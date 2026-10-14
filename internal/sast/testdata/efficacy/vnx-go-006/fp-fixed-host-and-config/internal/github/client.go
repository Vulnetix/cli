package github

import (
	"fmt"
	"net/http"
	"net/url"
)

type Config struct {
	WebhookURL string
	BaseURL    string
}

type Server struct {
	cfg    Config
	client *http.Client
}

// The host is fixed; the request only chooses a path under it.
func (s *Server) Repo(w http.ResponseWriter, r *http.Request) {
	owner := r.URL.Query().Get("owner")
	repo := r.URL.Query().Get("repo")
	resp, err := http.Get("https://api.github.com/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo))
	if err == nil {
		resp.Body.Close()
	}
	u := fmt.Sprintf("https://api.example.com/v1/users/%s", r.FormValue("id"))
	if resp, err := s.client.Get(u); err == nil {
		resp.Body.Close()
	}
}

// Configuration chooses these destinations, not the requester.
func (s *Server) Ping(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	req, _ := http.NewRequest(http.MethodPost, s.cfg.WebhookURL, nil)
	_, _ = s.client.Do(req)
	resp, err := s.client.Get(s.cfg.BaseURL + "/items/" + url.PathEscape(id))
	if err == nil {
		resp.Body.Close()
	}
}
