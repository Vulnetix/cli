package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
	"github.com/vulnetix/cli/v3/internal/sensor/siem"
)

type egressSeen struct {
	mu  sync.Mutex
	all []siem.EgressDecision
	got chan struct{}
}

func newEgressSeen() *egressSeen { return &egressSeen{got: make(chan struct{}, 16)} }

func (e *egressSeen) add(d siem.EgressDecision) {
	e.mu.Lock()
	e.all = append(e.all, d)
	e.mu.Unlock()
	e.got <- struct{}{}
}

func (e *egressSeen) wait(t *testing.T, n int) []siem.EgressDecision {
	t.Helper()
	for {
		e.mu.Lock()
		have := len(e.all)
		e.mu.Unlock()
		if have >= n {
			break
		}
		select {
		case <-e.got:
		case <-time.After(3 * time.Second):
			t.Fatalf("observed %d connections, want %d", have, n)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	return append([]siem.EgressDecision(nil), e.all...)
}

var stixRule = feed.Rule{RuleTable: "countermeasure", RuleUUID: "cm-1", RuleType: "STIX", DeployMode: "block",
	Body: `{"type":"bundle","objects":[{"type":"indicator","pattern":"[domain-name:value = 'evil.example']"}]}`}

func TestEgressObservesARefusalAtOnce(t *testing.T) {
	rules, verdicts := setup(t, decide.Enforce, []feed.Rule{stixRule})
	seen := newEgressSeen()
	p := &Egress{Rules: rules, Verdicts: verdicts, Observe: seen.add}

	r := httptest.NewRequest(http.MethodConnect, "https://c2.evil.example:443", nil)
	r.Host = "c2.evil.example:443"
	r.RemoteAddr = "10.0.0.9:40001"
	p.ServeHTTP(httptest.NewRecorder(), r)

	got := seen.wait(t, 1)[0]
	if got.Match == nil || got.Match.Verdict.Action != decide.Blocked || got.Target != "c2.evil.example:443" || got.Client != "10.0.0.9:40001" {
		t.Fatalf("refusal = %+v", got)
	}
}

func TestEgressObservesPlainHTTPWithItsBytes(t *testing.T) {
	rules, verdicts := setup(t, decide.Enforce, []feed.Rule{stixRule})
	seen := newEgressSeen()
	p := &Egress{Rules: rules, Verdicts: verdicts, Observe: seen.add}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("twelve bytes"))
	}))
	defer srv.Close()

	r := httptest.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	p.ServeHTTP(httptest.NewRecorder(), r)

	got := seen.wait(t, 1)[0]
	if got.Match != nil || got.Bytes != 12 || got.Method != http.MethodGet {
		t.Fatalf("plain http = %+v", got)
	}
	if got.RemoteAddr != strings.TrimPrefix(srv.URL, "http://") {
		t.Fatalf("remote addr = %q, want the server's", got.RemoteAddr)
	}
}

func TestEgressObservesATunnelWhenItEnds(t *testing.T) {
	rules, verdicts := setup(t, decide.Enforce, []feed.Rule{stixRule})
	seen := newEgressSeen()
	p := &Egress{Rules: rules, Verdicts: verdicts, Observe: seen.add}

	// An echo server stands in for the TLS destination.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 5)
		_, _ = io.ReadFull(c, buf)
		_, _ = c.Write(buf)
		_ = c.Close()
	}()
	proxySrv := httptest.NewServer(p)
	defer proxySrv.Close()

	c, err := net.Dial("tcp", strings.TrimPrefix(proxySrv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "CONNECT "+ln.Addr().String()+" HTTP/1.1\r\nHost: "+ln.Addr().String()+"\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT = %v %v", resp, err)
	}
	_, _ = io.WriteString(c, "hello")
	echo := make([]byte, 5)
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != "hello" {
		t.Fatalf("echo = %q %v", echo, err)
	}
	_ = c.Close()

	got := seen.wait(t, 1)[0]
	if got.Bytes != 10 || got.Method != http.MethodConnect || got.RemoteAddr != ln.Addr().String() {
		t.Fatalf("tunnel = %+v", got)
	}
}

func TestEgressObservesADialFailure(t *testing.T) {
	rules, verdicts := setup(t, decide.Enforce, []feed.Rule{stixRule})
	seen := newEgressSeen()
	p := &Egress{Rules: rules, Verdicts: verdicts, Observe: seen.add,
		Dial: func(string, string) (net.Conn, error) { return nil, io.ErrUnexpectedEOF }}
	r := httptest.NewRequest(http.MethodConnect, "https://fine.example:443", nil)
	r.Host = "fine.example:443"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("code = %d", w.Code)
	}
	if got := seen.wait(t, 1)[0]; got.Error == "" || got.Match != nil {
		t.Fatalf("dial failure = %+v", got)
	}
}

func TestTargetAddsTheSchemePort(t *testing.T) {
	get := httptest.NewRequest(http.MethodGet, "http://a.example/x", nil)
	if got := target("a.example", get); got != "a.example:80" {
		t.Fatalf("http = %q", got)
	}
	if got := target("a.example:8080", get); got != "a.example:8080" {
		t.Fatalf("explicit port = %q", got)
	}
	conn := httptest.NewRequest(http.MethodConnect, "https://a.example:443", nil)
	if got := target("a.example", conn); got != "a.example:443" {
		t.Fatalf("connect = %q", got)
	}
}
