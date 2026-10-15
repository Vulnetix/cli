package client

import "net/http"

func Report(body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(
		http.MethodPost,
~>		"http://telemetry.acme-corp.io/ingest",
		body,
	)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}
