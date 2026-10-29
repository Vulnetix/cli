// Package siem forwards every DNS and egress decision the sensor makes to
// Guardian, the Vulnetix SIEM, as dns_events and net_events rows.
//
// The sensor runs on a customer's machine, so it posts to the per-tenant
// events route with the customer's own Guardian ingest token, never to the
// multi-tenant producer route. The token decides the organisation; a row never
// carries a tenant.
//
// Forwarding must never slow a decision. DNS and Egress only append to a
// bounded buffer under a mutex; the HTTP work happens in Run. When the buffer
// is full the oldest rows are dropped and counted, and a batch the server
// refuses or cannot be reached for is dropped too: the console's Runtime page
// stays the record of what matched, and Guardian is a copy.
package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
)

// DefaultURL is Guardian's per-tenant events route.
const DefaultURL = "https://ingest.vulnetix.com/v1/ingest/events"

// Source is the source column every row carries.
const Source = "sensor"

const (
	defaultLimit      = 20000
	defaultBatch      = 1000
	defaultFlushEvery = 10 * time.Second
	defaultTimeout    = 10 * time.Second
	// maxPerRequest is the events route's own limit.
	maxPerRequest = 5000
	logEvery      = time.Minute
)

// Match is the rule a decision was taken under. A decision with no Match is a
// lookup or connection no indicator named, which the sensor allowed.
type Match struct {
	Rule      decide.RuleRef
	Indicator string
	Verdict   decide.Verdict
}

// DNSDecision is one lookup the DNS guard answered or refused.
type DNSDecision struct {
	Time time.Time
	// Client is who asked, host:port.
	Client  string
	QName   string
	QType   string
	RCode   string
	Answers []string
	Match   *Match
	// Error is set when the upstream resolver could not answer.
	Error string
}

// EgressDecision is one outbound connection the egress proxy allowed or
// refused.
type EgressDecision struct {
	Time time.Time
	// Client is the workload's side of the proxy connection, host:port.
	Client string
	// Target is what the client asked for, host:port.
	Target string
	// RemoteAddr is the address the proxy reached, ip:port, when it dialled.
	RemoteAddr string
	Method     string
	Bytes      int64
	Match      *Match
	Error      string
}

// Event is one row as the events route takes it.
type Event struct {
	Table string         `json:"table"`
	Row   map[string]any `json:"row"`
}

type request struct {
	Source string  `json:"source"`
	Events []Event `json:"events"`
}

// Forwarder buffers rows and posts them in batches.
type Forwarder struct {
	// URL is the events route; DefaultURL when empty.
	URL string
	// Token is the Guardian ingest token, gdn_...
	Token string
	// Host is the machine name every row carries.
	Host string

	Client     *http.Client
	Limit      int
	BatchSize  int
	FlushEvery time.Duration
	Logf       func(string, ...any)
	Now        func() time.Time

	mu       sync.Mutex
	buf      []Event
	dropped  int
	failed   int
	lastLog  time.Time
	wake     chan struct{}
	initOnce sync.Once
}

func (f *Forwarder) init() {
	f.initOnce.Do(func() {
		if f.URL == "" {
			f.URL = DefaultURL
		}
		if f.Client == nil {
			f.Client = &http.Client{Timeout: defaultTimeout}
		}
		if f.Limit <= 0 {
			f.Limit = defaultLimit
		}
		if f.BatchSize <= 0 {
			f.BatchSize = defaultBatch
		}
		f.BatchSize = min(f.BatchSize, maxPerRequest)
		if f.FlushEvery <= 0 {
			f.FlushEvery = defaultFlushEvery
		}
		if f.Logf == nil {
			f.Logf = log.Printf
		}
		if f.Now == nil {
			f.Now = time.Now
		}
		f.wake = make(chan struct{}, 1)
	})
}

// DNS queues a DNS decision. It never blocks on the network.
func (f *Forwarder) DNS(d DNSDecision) { f.add(DNSRow(f.Host, d)) }

// Egress queues an egress decision. It never blocks on the network.
func (f *Forwarder) Egress(d EgressDecision) { f.add(EgressRow(f.Host, d)) }

func (f *Forwarder) add(e Event) {
	f.init()
	f.mu.Lock()
	if len(f.buf) >= f.Limit {
		over := len(f.buf) - f.Limit + 1
		f.buf = f.buf[over:]
		f.dropped += over
	}
	f.buf = append(f.buf, e)
	full := len(f.buf) >= f.BatchSize
	f.mu.Unlock()
	if full {
		select {
		case f.wake <- struct{}{}:
		default:
		}
	}
}

// Dropped is how many rows were dropped since the forwarder started: pushed
// out of a full buffer, or in a batch that could not be delivered.
func (f *Forwarder) Dropped() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.dropped + f.failed
}

// Pending is how many rows wait to be sent.
func (f *Forwarder) Pending() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.buf)
}

// Run flushes every FlushEvery, or sooner when BatchSize rows wait, until ctx
// ends, then flushes once more.
func (f *Forwarder) Run(ctx context.Context) {
	f.init()
	tick := time.NewTicker(f.FlushEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			f.Flush(sctx)
			cancel()

			return
		case <-tick.C:
		case <-f.wake:
		}
		f.Flush(ctx)
	}
}

// Flush posts everything buffered, BatchSize rows to a request. A batch that
// fails is dropped and counted; it is not retried.
func (f *Forwarder) Flush(ctx context.Context) {
	f.init()
	for {
		f.mu.Lock()
		if len(f.buf) == 0 {
			f.mu.Unlock()

			return
		}
		n := min(len(f.buf), f.BatchSize)
		batch := append([]Event(nil), f.buf[:n]...)
		f.buf = f.buf[n:]
		f.mu.Unlock()

		if err := f.post(ctx, batch); err != nil {
			f.mu.Lock()
			f.failed += len(batch)
			f.mu.Unlock()
			f.logFailure(err, len(batch))

			return
		}
	}
}

// logFailure logs at most once a minute, with the running drop count, so a
// Guardian outage does not fill the host's log.
func (f *Forwarder) logFailure(err error, n int) {
	f.mu.Lock()
	now := f.Now()
	if !f.lastLog.IsZero() && now.Sub(f.lastLog) < logEvery {
		f.mu.Unlock()

		return
	}
	f.lastLog = now
	dropped := f.dropped + f.failed
	f.mu.Unlock()
	f.Logf("sensor: siem forward failed, %d events dropped (%d in all): %v", n, dropped, err)
}

func (f *Forwarder) post(ctx context.Context, batch []Event) error {
	body, err := json.Marshal(request{Source: Source, Events: batch})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+f.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode/100 != 2 {
		if resp.StatusCode == http.StatusUnauthorized {
			return errors.New("401 unauthorised: check the Guardian ingest token")
		}

		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}

	return nil
}

// DNSRow maps a DNS decision to a dns_events row.
func DNSRow(host string, d DNSDecision) Event {
	answers := d.Answers
	if answers == nil {
		answers = []string{}
	}
	row := map[string]any{
		"ts":      utc(d.Time),
		"host":    host,
		"qname":   strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d.QName)), "."),
		"qtype":   d.QType,
		"rcode":   d.RCode,
		"answers": answers,
	}
	if ip := hostOf(d.Client); ip != "" {
		row["src_ip"] = ip
	}
	raw := map[string]any{}
	decision(row, raw, d.Match)
	if d.Error != "" {
		raw["error"] = d.Error
	}
	row["raw"] = raw

	return Event{Table: "dns_events", Row: row}
}

// EgressRow maps an egress decision to a net_events row.
func EgressRow(host string, d EgressDecision) Event {
	row := map[string]any{
		"ts":        utc(d.Time),
		"host":      host,
		"proto":     "tcp",
		"bytes":     d.Bytes,
		"direction": "egress",
	}
	if h, p := splitHostPort(d.Client); h != "" {
		row["src_ip"] = h
		if p > 0 {
			row["src_port"] = p
		}
	}
	dstHost, dstPort := splitHostPort(d.Target)
	if dstHost != "" {
		if net.ParseIP(dstHost) != nil {
			row["dst_ip"] = dstHost
		} else {
			row["dst_host"] = strings.ToLower(dstHost)
		}
	}
	if ip, p := splitHostPort(d.RemoteAddr); ip != "" && net.ParseIP(ip) != nil {
		row["dst_ip"] = ip
		if dstPort == 0 {
			dstPort = p
		}
	}
	if dstPort > 0 {
		row["dst_port"] = dstPort
	}
	raw := map[string]any{}
	decision(row, raw, d.Match)
	if d.Method != "" {
		raw["method"] = d.Method
	}
	if d.Error != "" {
		raw["error"] = d.Error
	}
	row["raw"] = raw

	return Event{Table: "net_events", Row: row}
}

// decision fills action and policy, and puts what the columns cannot hold in
// raw. A hold refuses the lookup or connection while it lasts, so it is a
// block to the SIEM; raw keeps the sensor's own word.
func decision(row, raw map[string]any, m *Match) {
	if m == nil {
		row["action"] = "allow"
		raw["decision"] = string(decide.Allowed)
		raw["reason"] = "no indicator matched"

		return
	}
	row["action"] = "allow"
	if m.Verdict.Action == decide.Blocked || m.Verdict.Action == decide.Held {
		row["action"] = "block"
	}
	row["policy"] = m.Rule.Table + ":" + m.Rule.UUID
	raw["decision"] = string(m.Verdict.Action)
	raw["reason"] = m.Verdict.Reason
	raw["rule_table"] = m.Rule.Table
	raw["rule_uuid"] = m.Rule.UUID
	if m.Indicator != "" {
		raw["indicator"] = m.Indicator
	}
	if m.Verdict.Action == decide.Held && !m.Verdict.HoldUntil.IsZero() {
		raw["hold_until"] = utc(m.Verdict.HoldUntil)
	}
}

func utc(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}

	return t.UTC().Format(time.RFC3339Nano)
}

func hostOf(addr string) string {
	h, _ := splitHostPort(addr)

	return h
}

// splitHostPort accepts host:port, [v6]:port or a bare host.
func splitHostPort(addr string) (string, int) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", 0
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return strings.Trim(addr, "[]"), 0
	}
	port, _ := strconv.Atoi(p)

	return h, port
}
