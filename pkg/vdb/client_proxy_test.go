package vdb

import (
	"net/http"
	"reflect"
	"testing"

	"golang.org/x/net/http/httpproxy"
)

// A zero-value http.Transport has a nil Proxy and silently bypasses
// HTTP_PROXY/HTTPS_PROXY/NO_PROXY. That is how VDB calls used to escape a
// corporate proxy. These tests fail if the Proxy field is ever dropped again.
//
// Note: http.ProxyFromEnvironment reads the environment exactly once per
// process and caches the result, so a test cannot drive it with t.Setenv.
// The env-dependent semantics are asserted against httpproxy.FromEnvironment,
// which is the same resolver without the caching.

func TestSharedTransportUsesProxyFromEnvironment(t *testing.T) {
	if sharedTransport.Proxy == nil {
		t.Fatal("sharedTransport.Proxy is nil: VDB requests would bypass HTTP_PROXY/HTTPS_PROXY")
	}

	want := reflect.ValueOf(http.ProxyFromEnvironment).Pointer()
	got := reflect.ValueOf(sharedTransport.Proxy).Pointer()
	if got != want {
		t.Errorf("sharedTransport.Proxy is not http.ProxyFromEnvironment")
	}
}

// The behaviour the fix buys, asserted on the uncached resolver.
func TestProxyEnvironmentSemantics(t *testing.T) {
	const target = "https://api.vdb.vulnetix.com/v2/kev"

	tests := []struct {
		name      string
		httpsuck  string
		noProxy   string
		wantProxy string
	}{
		{name: "HTTPS_PROXY is honoured", httpsuck: "http://proxy.example.com:8080", wantProxy: "proxy.example.com:8080"},
		{name: "NO_PROXY exempts the host", httpsuck: "http://proxy.example.com:8080", noProxy: "api.vdb.vulnetix.com"},
		{name: "no proxy configured", httpsuck: ""},
	}

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proxyFunc := (&httpproxy.Config{
				HTTPSProxy: tc.httpsuck,
				NoProxy:    tc.noProxy,
			}).ProxyFunc()

			proxyURL, err := proxyFunc(req.URL)
			if err != nil {
				t.Fatalf("proxy resolver: %v", err)
			}

			if tc.wantProxy == "" {
				if proxyURL != nil {
					t.Errorf("expected no proxy, got %v", proxyURL)
				}
				return
			}
			if proxyURL == nil {
				t.Fatalf("expected proxy %q, got none", tc.wantProxy)
			}
			if proxyURL.Host != tc.wantProxy {
				t.Errorf("proxy host = %q, want %q", proxyURL.Host, tc.wantProxy)
			}
		})
	}
}

// Every client built by this package must route through sharedTransport, or it
// inherits http.DefaultTransport and this fix silently does not apply to it.
func TestClientsUseSharedTransport(t *testing.T) {
	for name, client := range map[string]*Client{
		"NewClient": NewClient("org", "secret"),
	} {
		transport, ok := client.HTTPClient.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("%s: HTTPClient.Transport is %T, want *http.Transport", name, client.HTTPClient.Transport)
		}
		if transport != sharedTransport {
			t.Errorf("%s: does not use sharedTransport", name)
		}
	}
}

// Guard the assumption the audit relied on: every client that leaves Transport
// nil inherits http.DefaultTransport, which already reads the proxy env.
func TestDefaultTransportReadsProxyEnvironment(t *testing.T) {
	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Skipf("http.DefaultTransport is %T", http.DefaultTransport)
	}
	if dt.Proxy == nil {
		t.Fatal("http.DefaultTransport.Proxy is nil; the audit's assumption no longer holds")
	}
}
