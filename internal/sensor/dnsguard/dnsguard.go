// Package dnsguard is a DNS forwarder that checks every name a workload looks
// up against the feeds' domain indicators.
//
// It catches what the egress proxy cannot: software that ignores HTTPS_PROXY
// still resolves names, and a lookup of a command-and-control domain is the
// earliest sign of a compromise. Point the workload's resolver at it
// (/etc/resolv.conf, the task's dnsServers, a pod's dnsConfig).
//
// A refused lookup answers NXDOMAIN, which every client handles. Anything the
// guard cannot parse is forwarded untouched: it fails open like the proxies.
package dnsguard

import (
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/engine"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
)

// Guard forwards DNS over UDP.
type Guard struct {
	// Upstream is the resolver lookups go to, host:port.
	Upstream string
	Rules    func() *engine.Set
	Verdicts *decide.Engine
	Report   func(uplink.Event)
	Now      func() time.Time
}

func (g *Guard) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}

	return time.Now()
}

// Serve answers on conn until ctx ends.
func (g *Guard) Serve(ctx context.Context, conn net.PacketConn) error {
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return err
		}
		query := append([]byte(nil), buf[:n]...)
		go func() {
			if reply := g.Answer(query); reply != nil {
				_, _ = conn.WriteTo(reply, addr)
			}
		}()
	}
}

// Answer returns the reply to one query: NXDOMAIN when the name is refused,
// otherwise whatever the upstream resolver said.
func (g *Guard) Answer(query []byte) []byte {
	if reply, refused := g.check(query); refused {
		return reply
	}
	reply, err := forward(g.Upstream, query)
	if err != nil {
		log.Printf("sensor: dns upstream %s: %v", g.Upstream, err)

		return nil
	}

	return reply
}

// check decides about the query's name. It never refuses what it cannot parse.
func (g *Guard) check(query []byte) (reply []byte, refused bool) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("sensor: dns check failed, forwarding: %v", rec)
			reply, refused = nil, false
		}
	}()
	set := g.Rules()
	if set == nil || len(set.IOC.Domains) == 0 {
		return nil, false
	}
	var p dnsmessage.Parser
	header, err := p.Start(query)
	if err != nil {
		return nil, false
	}
	q, err := p.Question()
	if err != nil {
		return nil, false
	}
	name := strings.TrimSuffix(q.Name.String(), ".")
	rule, matched, ok := set.IOC.MatchHost(name)
	if !ok {
		return nil, false
	}

	now := g.now()
	// An answer withheld is undone by answering the next lookup, so guard
	// may hold it.
	v := g.Verdicts.Decide(decide.Match{Rule: rule, Subject: name, Reversible: true}, now)
	if g.Report != nil {
		ev := uplink.Event{
			EventKey: newKey(), RuleTable: rule.Table, RuleUUID: rule.UUID, Lane: lane(rule.Table),
			SubjectKind: "dns", Subject: clip(name), Action: string(v.Action),
			Detail:     map[string]any{"indicator": matched, "type": q.Type.String(), "reason": v.Reason},
			ObservedAt: now.UnixMilli(),
		}
		if v.Action == decide.Held {
			ev.HoldExpiresAt = v.HoldUntil.UnixMilli()
		}
		g.Report(ev)
	}
	if v.Action == decide.Allowed {
		return nil, false
	}

	return nxdomain(header, q), true
}

func nxdomain(h dnsmessage.Header, q dnsmessage.Question) []byte {
	h.Response = true
	h.RCode = dnsmessage.RCodeNameError
	h.RecursionAvailable = true
	b := dnsmessage.NewBuilder(nil, h)
	_ = b.StartQuestions()
	_ = b.Question(q)
	out, err := b.Finish()
	if err != nil {
		return nil
	}

	return out
}

func forward(upstream string, query []byte) ([]byte, error) {
	if upstream == "" {
		return nil, errors.New("no upstream resolver")
	}
	conn, err := net.DialTimeout("udp", upstream, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

// UpstreamFromResolvConf reads the first nameserver in a resolv.conf, so the
// guard forwards to whatever the host used before it was put in front.
func UpstreamFromResolvConf(body string) string {
	for _, line := range strings.Split(body, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			return net.JoinHostPort(f[1], "53")
		}
	}

	return ""
}

func lane(table string) string {
	if table == "countermeasure" {
		return "countermeasure"
	}

	return "ioc"
}

func clip(s string) string {
	if len(s) > 512 {
		return s[:512]
	}

	return s
}
