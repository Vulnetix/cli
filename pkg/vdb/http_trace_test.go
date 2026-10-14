package vdb

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestHTTPTraceLineCarriesNoSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	defer srv.Close()
	var out bytes.Buffer
	traceOut = &out
	defer func() { traceOut = os.Stderr }()

	req, _ := http.NewRequest("POST", srv.URL+"/v2/cli.sca?token=s3cret", strings.NewReader(`{"secret":"s3cret"}`))
	req.Header.Set("Authorization", "Bearer s3cret")
	resp, err := (&http.Client{Transport: tracingRT{http.DefaultTransport}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	line := out.String()
	if !regexp.MustCompile(`^\[http#\d+\] \+ *\d+ms +\d+ms 418 POST 127\.0\.0\.1:\d+/v2/cli\.sca\n$`).MatchString(line) {
		t.Fatalf("unexpected trace line %q", line)
	}
	if strings.Contains(line, "s3cret") {
		t.Fatalf("trace line leaked a secret: %q", line)
	}
}
