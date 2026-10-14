package vdb

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// VULNETIX_HTTP_TRACE=1 prints one stderr line per HTTP request the process
// makes: its sequence number, start offset from process start, duration,
// status, method, host and path. Never headers, query strings or bodies, so a
// trace can be shared without leaking credentials. A scan is mostly round
// trips, and this is how to see which ones a slow scan waited on.
//
//	[http#5] +  2241ms   3836ms 200 POST api.vdb.vulnetix.com/v2/cli.sca net=0ms
//
// net= is the part of the duration spent setting up the connection (DNS, TCP
// connect, TLS handshake; 0 on a reused connection), so a slow network can
// be told apart from a slow server.

var (
	traceStart = time.Now()
	traceSeq   atomic.Int64
	traceOut   io.Writer = os.Stderr
)

func httpTraceEnabled() bool { return os.Getenv("VULNETIX_HTTP_TRACE") != "" }

type tracingRT struct{ next http.RoundTripper }

func (t tracingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	n := traceSeq.Add(1)
	s := time.Now()
	var mu sync.Mutex
	var netDur time.Duration
	var dnsS, connS, tlsS time.Time
	add := func(from time.Time) {
		if !from.IsZero() {
			mu.Lock()
			netDur += time.Since(from)
			mu.Unlock()
		}
	}
	ct := &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { dnsS = time.Now() },
		DNSDone:           func(httptrace.DNSDoneInfo) { add(dnsS) },
		ConnectStart:      func(string, string) { mu.Lock(); connS = time.Now(); mu.Unlock() },
		ConnectDone:       func(string, string, error) { mu.Lock(); c := connS; mu.Unlock(); add(c) },
		TLSHandshakeStart: func() { tlsS = time.Now() },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { add(tlsS) },
	}
	r = r.WithContext(httptrace.WithClientTrace(r.Context(), ct))
	resp, err := t.next.RoundTrip(r)
	code := 0
	if resp != nil {
		code = resp.StatusCode
	}
	mu.Lock()
	nd := netDur
	mu.Unlock()
	fmt.Fprintf(traceOut, "[http#%d] +%6dms %6dms %d %s %s%s net=%dms\n", n, s.Sub(traceStart).Milliseconds(), time.Since(s).Milliseconds(), code, r.Method, r.URL.Host, r.URL.Path, nd.Milliseconds())
	return resp, err
}

// traceTransport wraps rt with the request trace when it is enabled.
func traceTransport(rt http.RoundTripper) http.RoundTripper {
	if !httpTraceEnabled() {
		return rt
	}
	return tracingRT{rt}
}

func init() {
	// Clients built on http.DefaultTransport (licence registries, deps.dev,
	// GitHub, analytics) are traced too.
	if httpTraceEnabled() {
		http.DefaultTransport = tracingRT{http.DefaultTransport}
	}
}
