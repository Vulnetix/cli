package dash

import gapi "github.com/grafana/grafana-api-golang-client"

func newClient() (*gapi.Client, error) {
	return gapi.New("https://grafana.acme.internal", gapi.Config{
~>		APIKey: "glsa_@@sample:[A-Za-z0-9]{32}@@_@@sample:[a-f0-9]{8}@@",
	})
}
