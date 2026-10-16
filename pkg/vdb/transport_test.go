package vdb

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A scan's requests share one HTTP/2 connection, and a blocked write on it froze every
// request for hours because no deadline reaches a write. The shared transport must close
// a connection that cannot make write progress or has gone silent.
func TestSharedTransportDetectsAStalledHTTP2Connection(t *testing.T) {
	cfg := sharedTransport.HTTP2
	if cfg == nil {
		t.Fatal("the shared transport must configure HTTP/2 health checks")
	}
	if cfg.WriteByteTimeout <= 0 {
		t.Error("WriteByteTimeout must be set so a blocked body write closes the connection")
	}
	if cfg.SendPingTimeout <= 0 || cfg.PingTimeout <= 0 {
		t.Error("SendPingTimeout and PingTimeout must be set so a silent connection is closed")
	}
	if cfg.WriteByteTimeout > time.Minute {
		t.Errorf("WriteByteTimeout %v is longer than the 75s a batch is given", cfg.WriteByteTimeout)
	}
}

// The health checks must not break an ordinary HTTP/2 exchange.
func TestSharedTransportStillSpeaksHTTP2(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Proto", r.Proto)
		_, _ = w.Write([]byte(strings.ToUpper(string(b))))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	tr := sharedTransport.Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test server
	tr.ForceAttemptHTTP2 = true
	defer tr.CloseIdleConnections()

	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Post(srv.URL, "text/plain", strings.NewReader("ping"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "PING" || resp.ProtoMajor != 2 {
		t.Fatalf("got %q over HTTP/%d, want PING over HTTP/2", got, resp.ProtoMajor)
	}
}
