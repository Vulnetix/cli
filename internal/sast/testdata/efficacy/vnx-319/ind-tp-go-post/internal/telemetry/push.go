package telemetry

import (
	"bytes"
	"net/http"
)

func Push(body []byte) error {
~>	resp, err := http.Post("http://ingest.metricsvendor.io/v1/points", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
