package gh

import (
	"net/http"
	"net/url"
	"strconv"
)

type Config struct {
	WebhookURL string
	SidecarPort int
}

func Repo(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get("https://api.github.com/repos/" + url.PathEscape(r.FormValue("owner")) + "/" + url.PathEscape(r.FormValue("repo")))
	if err == nil {
		resp.Body.Close()
	}
}

func Notify(cfg Config, r *http.Request) error {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, cfg.WebhookURL, nil)
	if err != nil {
		return err
	}
	_, err = http.DefaultClient.Do(req)
	return err
}

func Sidecar(cfg Config, r *http.Request) (*http.Response, error) {
	return http.Get("http://127.0.0.1:" + strconv.Itoa(cfg.SidecarPort) + "/healthz?probe=" + url.QueryEscape(r.FormValue("probe")))
}
