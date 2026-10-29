package proxy

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/siem"
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
	// Observe, when set, receives every connection the proxy refuses or
	// carries, matched or not (the --forward siem copy). A refusal is
	// observed at once; a carried connection when it ends, with its bytes.
	// It must not block.
	Observe func(siem.EgressDecision)
	Dial    func(network, addr string) (net.Conn, error)
	Now     func() time.Time
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
	refused, until, match := p.check(host)
	obs := siem.EgressDecision{Time: p.now(), Client: r.RemoteAddr, Target: target(host, r), Method: r.Method, Match: match}
	if refused != "" {
		p.observe(obs)
		refuse(w, refused, until)

		return
	}

	if r.Method == http.MethodConnect {
		p.tunnel(w, r, obs)

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
	if p.Observe != nil {
		r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				if info.Conn != nil {
					obs.RemoteAddr = info.Conn.RemoteAddr().String()
				}
			},
		}))
	}
	r.RequestURI = ""
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authorization")
	resp, err := transport.RoundTrip(r)
	if err != nil {
		obs.Error = err.Error()
		p.observe(obs)
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
	n, _ := io.Copy(w, resp.Body)
	obs.Bytes = n
	p.observe(obs)
}

// target is host:port as the client asked for it, with the scheme's port
// when the request named none.
func target(host string, r *http.Request) string {
	if _, _, err := net.SplitHostPort(host); err == nil || host == "" {
		return host
	}
	port := "80"
	if r.Method == http.MethodConnect || r.URL.Scheme == "https" {
		port = "443"
	}

	return net.JoinHostPort(host, port)
}

// observe hands one decision to Observe. A panic there costs the copy, never
// the connection.
func (p *Egress) observe(d siem.EgressDecision) {
	if p.Observe == nil {
		return
	}
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("sensor: egress observe failed: %v", rec)
		}
	}()
	p.Observe(d)
}

// check returns "blocked" or "held" when the destination must be refused, and
// the rule that matched, if any.
func (p *Egress) check(host string) (outcome string, until time.Time, match *siem.Match) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("sensor: egress check failed, passing it through: %v", rec)
			outcome, match = "", nil
		}
	}()
	set := p.Rules.Load()
	if set == nil {
		return "", time.Time{}, nil
	}
	rule, matched, ok := set.IOC.MatchHost(host)
	if !ok {
		return "", time.Time{}, nil
	}
	now := p.now()
	// A new outbound connection refused is undone by allowing the next one,
	// so it is reversible and guard may hold it.
	v := p.Verdicts.Decide(decide.Match{Rule: rule, Subject: clip(host), Reversible: true}, now)
	match = &siem.Match{Rule: rule, Indicator: matched, Verdict: v}
	if p.Report != nil {
		p.Report(event(rule, "connection", clip(host), v, now, map[string]any{"indicator": matched, "reason": v.Reason}))
	}
	switch v.Action {
	case decide.Blocked:
		return "blocked", time.Time{}, match
	case decide.Held:
		return "held", v.HoldUntil, match
	}

	return "", time.Time{}, match
}

func (p *Egress) tunnel(w http.ResponseWriter, r *http.Request, obs siem.EgressDecision) {
	dial := p.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 15 * time.Second}
		dial = d.Dial
	}
	upstream, err := dial("tcp", r.Host)
	if err != nil {
		obs.Error = err.Error()
		p.observe(obs)
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)

		return
	}
	if ra := upstream.RemoteAddr(); ra != nil {
		obs.RemoteAddr = ra.String()
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
	var sent int64
	if buffered.Reader.Buffered() > 0 {
		pending := make([]byte, buffered.Reader.Buffered())
		_, _ = buffered.Read(pending)
		n, _ := upstream.Write(pending)
		sent += int64(n)
	}
	out := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(upstream, client)
		_ = upstream.Close()
		out <- n
	}()
	received, _ := io.Copy(client, upstream)
	_ = client.Close()
	if p.Observe != nil {
		sent += <-out
		obs.Bytes = sent + received
		p.observe(obs)
	}
}
