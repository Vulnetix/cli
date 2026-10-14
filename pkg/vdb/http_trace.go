package vdb

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// VULNETIX_HTTP_TRACE=1 prints one stderr line per HTTP request the process
// makes: its sequence number, start offset from process start, duration,
// status, method, host and path. Never headers, query strings or bodies, so a
// trace can be shared without leaking credentials. A scan is mostly round
// trips, and this is how to see which ones a slow scan waited on.
//
//	[http#5] +  2241ms   3836ms 200 POST api.vdb.vulnetix.com/v2/cli.sca

var (
	traceStart          = time.Now()
	traceSeq            atomic.Int64
	traceOut  io.Writer = os.Stderr
)

func httpTraceEnabled() bool { return os.Getenv("VULNETIX_HTTP_TRACE") != "" }

type tracingRT struct{ next http.RoundTripper }

func (t tracingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	n := traceSeq.Add(1)
	s := time.Now()
	resp, err := t.next.RoundTrip(r)
	code := 0
	if resp != nil {
		code = resp.StatusCode
	}
	fmt.Fprintf(traceOut, "[http#%d] +%6dms %6dms %d %s %s%s\n", n, s.Sub(traceStart).Milliseconds(), time.Since(s).Milliseconds(), code, r.Method, r.URL.Host, r.URL.Path)
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
