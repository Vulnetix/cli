// Package proxy puts the sensor in the request path.
//
// Reverse sits in front of a workload's port and runs the HTTP engines over
// each request; Egress is a forward proxy for the workload's outbound calls and
// checks each destination against the indicator set. Both ask the verdict
// engine what to do and report what they did.
//
// Both fail open. A panic in inspection, a rule set that has not loaded, or a
// request too large to buffer passes through untouched: the sensor protecting
// a workload must never be the reason it is down.
package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/engine"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
)

// Rules is the compiled set the proxies read, swapped atomically when a feed
// refresh compiles a new one.
type Rules struct{ p atomic.Pointer[engine.Set] }

// Load returns the current set, or nil before the first load.
func (r *Rules) Load() *engine.Set { return r.p.Load() }

// Store installs a new set.
func (r *Rules) Store(s *engine.Set) { r.p.Store(s) }

// Reporter receives every event the proxies produce.
type Reporter func(uplink.Event)

const subjectMax = 512

// Reverse is the inbound proxy.
type Reverse struct {
	Upstream *url.URL
	Rules    *Rules
	Verdicts *decide.Engine
	Report   Reporter
	// HealthPaths are paths a load balancer probes. A match on one is
	// reported and never held.
	HealthPaths []string
	// BodyLimit is how much of a body is inspected. Default 1 MiB.
	BodyLimit int64
	Now       func() time.Time

	proxy *httputil.ReverseProxy
}

func (p *Reverse) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}

	return time.Now()
}

func (p *Reverse) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.proxy == nil {
		p.proxy = httputil.NewSingleHostReverseProxy(p.Upstream)
	}
	if held, until := p.inspect(r); held != "" {
		refuse(w, held, until)

		return
	}
	p.proxy.ServeHTTP(w, r)
}

// inspect returns "blocked" or "held" when the request must not go through,
// and "" when it may.
func (p *Reverse) inspect(r *http.Request) (outcome string, until time.Time) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("sensor: request inspection failed, passing it through: %v", rec)
			outcome = ""
		}
	}()
	set := p.Rules.Load()
	if set == nil {
		return "", time.Time{}
	}

	limit := p.BodyLimit
	if limit <= 0 {
		limit = 1 << 20
	}
	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		buf, err := io.ReadAll(io.LimitReader(r.Body, limit))
		if err != nil {
			return "", time.Time{}
		}
		body = buf
		// What was read is put back in front of what was not, so the
		// upstream sees the whole body whatever was inspected.
		r.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(buf), r.Body), Closer: r.Body}
	}

	now := p.now()
	subject := clip(r.Method + " " + r.URL.Path)
	health := p.isHealth(r.URL.Path)
	for _, hit := range set.InspectRequest(r, body) {
		v := p.Verdicts.Decide(decide.Match{Rule: hit.Rule, Subject: subject, Reversible: true, HealthCheck: health}, now)
		p.report(hit.Rule, "request", subject, v, now, map[string]any{"match": clip(hit.Detail), "reason": v.Reason})
		switch v.Action {
		case decide.Blocked:
			outcome = "blocked"
		case decide.Held:
			if outcome == "" {
				outcome, until = "held", v.HoldUntil
			}
		}
	}

	return outcome, until
}

func (p *Reverse) isHealth(path string) bool {
	for _, h := range p.HealthPaths {
		if path == h {
			return true
		}
	}

	return false
}

func (p *Reverse) report(rule decide.RuleRef, kind, subject string, v decide.Verdict, now time.Time, detail map[string]any) {
	if p.Report == nil {
		return
	}
	p.Report(event(rule, kind, subject, v, now, detail))
}

func event(rule decide.RuleRef, kind, subject string, v decide.Verdict, now time.Time, detail map[string]any) uplink.Event {
	e := uplink.Event{
		EventKey:    newKey(),
		RuleTable:   rule.Table,
		RuleUUID:    rule.UUID,
		Lane:        laneFor(rule.Table),
		SubjectKind: kind,
		Subject:     subject,
		Action:      string(v.Action),
		Detail:      detail,
		ObservedAt:  now.UnixMilli(),
	}
	if v.Action == decide.Held {
		e.HoldExpiresAt = v.HoldUntil.UnixMilli()
	}

	return e
}

func laneFor(table string) string {
	switch table {
	case "virtual_patch":
		return "virtual-patch"
	case "countermeasure":
		return "countermeasure"
	default:
		return "ioc"
	}
}

func refuse(w http.ResponseWriter, outcome string, until time.Time) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	if outcome == "held" {
		_, _ = fmt.Fprintf(w, "This request is held for review by the site's security team until %s.\n", until.UTC().Format(time.RFC3339))

		return
	}
	_, _ = io.WriteString(w, "This request was blocked by the site's security policy.\n")
}

type readCloser struct {
	io.Reader
	io.Closer
}

func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}

		return r
	}, s)
	if r := []rune(s); len(r) > subjectMax {
		return string(r[:subjectMax])
	}

	return s
}

func newKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:])

	return hex.EncodeToString(b[:])
}
