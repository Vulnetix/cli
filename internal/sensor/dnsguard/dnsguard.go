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
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/engine"
	"github.com/vulnetix/cli/v3/internal/sensor/siem"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
)

// Guard forwards DNS over UDP.
type Guard struct {
	// Upstream is the resolver lookups go to, host:port.
	Upstream string
	Rules    func() *engine.Set
	Verdicts *decide.Engine
	Report   func(uplink.Event)
	// Observe, when set, receives every lookup the guard answers or
	// refuses, matched or not (the --forward siem copy). It must not block.
	Observe func(siem.DNSDecision)
	Now     func() time.Time
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
		client := addr.String()
		go func() {
			if reply := g.answer(query, client); reply != nil {
				_, _ = conn.WriteTo(reply, addr)
			}
		}()
	}
}

// Answer returns the reply to one query: NXDOMAIN when the name is refused,
// otherwise whatever the upstream resolver said.
func (g *Guard) Answer(query []byte) []byte { return g.answer(query, "") }

func (g *Guard) answer(query []byte, client string) []byte {
	reply, refused, obs := g.check(query)
	if refused {
		if obs != nil {
			obs.RCode = "NXDOMAIN"
			g.observe(*obs, client)
		}

		return reply
	}
	reply, err := forward(g.Upstream, query)
	if err != nil {
		log.Printf("sensor: dns upstream %s: %v", g.Upstream, err)
		if obs != nil {
			obs.Error = err.Error()
			g.observe(*obs, client)
		}

		return nil
	}
	if obs != nil {
		obs.RCode, obs.Answers = parseReply(reply)
		g.observe(*obs, client)
	}

	return reply
}

// observe hands one decision to Observe. A panic there costs the copy, never
// the answer.
func (g *Guard) observe(d siem.DNSDecision, client string) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("sensor: dns observe failed: %v", rec)
		}
	}()
	d.Client = client
	g.Observe(d)
}

// check decides about the query's name. It never refuses what it cannot
// parse. obs is the decision to observe: nil when there is no Observe, or the
// query did not parse.
func (g *Guard) check(query []byte) (reply []byte, refused bool, obs *siem.DNSDecision) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("sensor: dns check failed, forwarding: %v", rec)
			reply, refused, obs = nil, false, nil
		}
	}()
	set := g.Rules()
	hasDomains := set != nil && len(set.IOC.Domains) > 0
	if !hasDomains && g.Observe == nil {
		return nil, false, nil
	}
	var p dnsmessage.Parser
	header, err := p.Start(query)
	if err != nil {
		return nil, false, nil
	}
	q, err := p.Question()
	if err != nil {
		return nil, false, nil
	}
	name := strings.TrimSuffix(q.Name.String(), ".")
	now := g.now()
	if g.Observe != nil {
		obs = &siem.DNSDecision{Time: now, QName: name, QType: recordType(q.Type)}
	}
	if !hasDomains {
		return nil, false, obs
	}
	rule, matched, ok := set.IOC.MatchHost(name)
	if !ok {
		return nil, false, obs
	}

	// An answer withheld is undone by answering the next lookup, so guard
	// may hold it.
	v := g.Verdicts.Decide(decide.Match{Rule: rule, Subject: name, Reversible: true}, now)
	if obs != nil {
		obs.Match = &siem.Match{Rule: rule, Indicator: matched, Verdict: v}
	}
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
		return nil, false, obs
	}

	return nxdomain(header, q), true, obs
}

// recordType is the type as resolver logs name it: A, AAAA, TXT.
func recordType(t dnsmessage.Type) string {
	return strings.TrimPrefix(t.String(), "Type")
}

// rcodeName is the RFC 1035 mnemonic resolver logs use (NOERROR, NXDOMAIN),
// not dnsmessage's Go name (RCodeSuccess).
func rcodeName(c dnsmessage.RCode) string {
	switch c {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	}

	return strconv.Itoa(int(c))
}

// parseReply reads the response code and the answers a reply carries. What it
// cannot parse is left out; the reply itself goes back to the client
// untouched.
func parseReply(reply []byte) (rcode string, answers []string) {
	var p dnsmessage.Parser
	h, err := p.Start(reply)
	if err != nil {
		return "", nil
	}
	rcode = rcodeName(h.RCode)
	if err := p.SkipAllQuestions(); err != nil {
		return rcode, nil
	}
	for len(answers) < 64 {
		ah, err := p.AnswerHeader()
		if err != nil {
			break
		}
		var ans string
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return rcode, answers
			}
			ans = net.IP(r.A[:]).String()
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return rcode, answers
			}
			ans = net.IP(r.AAAA[:]).String()
		case dnsmessage.TypeCNAME:
			r, err := p.CNAMEResource()
			if err != nil {
				return rcode, answers
			}
			ans = strings.TrimSuffix(r.CNAME.String(), ".")
		default:
			if err := p.SkipAnswer(); err != nil {
				return rcode, answers
			}

			continue
		}
		answers = append(answers, ans)
	}

	return rcode, answers
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
