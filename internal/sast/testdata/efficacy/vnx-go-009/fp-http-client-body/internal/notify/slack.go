package notify

import (
	"bytes"
	"net/http"
	"text/template"
)

var msg = template.Must(template.New("slack").Parse(`{"text": "Deploy {{.Version}} finished"}`))

// Post renders a JSON body for an outgoing webhook; nothing is served.
func Post(client *http.Client, url, version string) error {
	var body bytes.Buffer
	if err := msg.Execute(&body, map[string]string{"Version": version}); err != nil {
		return err
	}
	resp, err := client.Post(url, "application/json", &body)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
