package proxy

import (
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
)

// Egress is a forward proxy for a workload's outbound calls: HTTP CONNECT for
// TLS, and absolute-URI requests for plain HTTP. It never decrypts; it sees
// the host a client asks for, which is what an indicator names.
//
// A workload reaches it through HTTPS_PROXY and HTTP_PROXY, which most SDKs
// honour. One that ignores them is not covered here, and the DNS check is the
// layer that catches it.
type Egress struct {
	Rules    *Rules
	Verdicts *decide.Engine
	Report   Reporter
	Dial     func(network, addr string) (net.Conn, error)
	Now      func() time.Time
	// Transport forwards plain-HTTP requests. Default http.DefaultTransport.
	Transport http.RoundTripper
}

func (p *Egress) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}

	return time.Now()
}

func (p *Egress) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if r.Method != http.MethodConnect && r.URL.Host != "" {
		host = r.URL.Host
	}
	if refused, until := p.check(host); refused != "" {
		refuse(w, refused, until)

		return
	}

	if r.Method == http.MethodConnect {
		p.tunnel(w, r)

		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "this is a forward proxy; send an absolute URL", http.StatusBadRequest)

		return
	}
	transport := p.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	r.RequestURI = ""
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authorization")
	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)

		return
	}
	defer func() { _ = resp.Body.Close() }()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// check returns "blocked" or "held" when the destination must be refused.
func (p *Egress) check(host string) (outcome string, until time.Time) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("sensor: egress check failed, passing it through: %v", rec)
			outcome = ""
		}
	}()
	set := p.Rules.Load()
	if set == nil {
		return "", time.Time{}
	}
	rule, matched, ok := set.IOC.MatchHost(host)
	if !ok {
		return "", time.Time{}
	}
	now := p.now()
	// A new outbound connection refused is undone by allowing the next one,
	// so it is reversible and guard may hold it.
	v := p.Verdicts.Decide(decide.Match{Rule: rule, Subject: clip(host), Reversible: true}, now)
	if p.Report != nil {
		p.Report(event(rule, "connection", clip(host), v, now, map[string]any{"indicator": matched, "reason": v.Reason}))
	}
	switch v.Action {
	case decide.Blocked:
		return "blocked", time.Time{}
	case decide.Held:
		return "held", v.HoldUntil
	}

	return "", time.Time{}
}

func (p *Egress) tunnel(w http.ResponseWriter, r *http.Request) {
	dial := p.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 15 * time.Second}
		dial = d.Dial
	}
	upstream, err := dial("tcp", r.Host)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)

		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "tunnelling is not supported here", http.StatusInternalServerError)

		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()

		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if buffered.Reader.Buffered() > 0 {
		pending := make([]byte, buffered.Reader.Buffered())
		_, _ = buffered.Read(pending)
		_, _ = upstream.Write(pending)
	}
	go func() {
		_, _ = io.Copy(upstream, client)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
}
