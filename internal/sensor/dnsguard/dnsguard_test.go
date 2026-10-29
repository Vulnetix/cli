package dnsguard

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/engine"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
)

func query(t *testing.T, name string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}

	return out
}

// fakeResolver answers every query with an empty NOERROR reply.
func fakeResolver(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, _ := p.Start(buf[:n])
			q, _ := p.Question()
			h.Response = true
			b := dnsmessage.NewBuilder(nil, h)
			_ = b.StartQuestions()
			_ = b.Question(q)
			out, _ := b.Finish()
			_, _ = pc.WriteTo(out, addr)
		}
	}()

	return pc.LocalAddr().String()
}

func guard(t *testing.T, mode decide.Mode) (*Guard, *[]uplink.Event) {
	t.Helper()
	set, _ := engine.Compile([]feed.Rule{{RuleTable: "countermeasure", RuleUUID: "cm", RuleType: "STIX", DeployMode: "block",
		Body: `{"type":"bundle","objects":[{"type":"indicator","pattern":"[domain-name:value = 'evil.example']"}]}`}})
	v := decide.New(mode, decide.Config{})
	v.SetRules([]decide.Rule{{Ref: decide.RuleRef{Table: "countermeasure", UUID: "cm"}, Mode: decide.Block, Verified: true}})
	var events []uplink.Event

	return &Guard{Upstream: fakeResolver(t), Rules: func() *engine.Set { return set }, Verdicts: v,
		Report: func(e uplink.Event) { events = append(events, e) }}, &events
}

func rcode(t *testing.T, reply []byte) dnsmessage.RCode {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(reply)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != 7 {
		t.Fatal("the reply must carry the query's id")
	}

	return h.RCode
}

func TestEnforceRefusesAnIndicatorAndForwardsTheRest(t *testing.T) {
	g, events := guard(t, decide.Enforce)
	if rc := rcode(t, g.Answer(query(t, "c2.evil.example."))); rc != dnsmessage.RCodeNameError {
		t.Fatalf("indicator = %v, want NXDOMAIN", rc)
	}
	if len(*events) != 1 || (*events)[0].SubjectKind != "dns" || (*events)[0].Action != "blocked" {
		t.Fatalf("events = %+v", *events)
	}
	if rc := rcode(t, g.Answer(query(t, "example.com."))); rc != dnsmessage.RCodeSuccess {
		t.Fatalf("clean name = %v", rc)
	}
}

func TestMonitorReportsAndAnswers(t *testing.T) {
	g, events := guard(t, decide.Monitor)
	if rc := rcode(t, g.Answer(query(t, "evil.example."))); rc != dnsmessage.RCodeSuccess {
		t.Fatalf("monitor must still answer: %v", rc)
	}
	if len(*events) != 1 || (*events)[0].Action != "allowed" {
		t.Fatalf("events = %+v", *events)
	}
}

func TestGarbageIsForwardedNotRefused(t *testing.T) {
	g, events := guard(t, decide.Enforce)
	if reply, refused, _ := g.check([]byte{1, 2, 3}); refused || reply != nil {
		t.Fatal("an unparseable packet is forwarded")
	}
	if len(*events) != 0 {
		t.Fatal("nothing to report")
	}
}

func TestServe(t *testing.T) {
	g, _ := guard(t, decide.Enforce)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = g.Serve(ctx, pc) }()

	c, _ := net.Dial("udp", pc.LocalAddr().String())
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write(query(t, "evil.example."))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if rcode(t, buf[:n]) != dnsmessage.RCodeNameError {
		t.Fatal("served answer was not NXDOMAIN")
	}
}

func TestUpstreamFromResolvConf(t *testing.T) {
	if got := UpstreamFromResolvConf("# x\nsearch a\nnameserver 10.0.0.2\nnameserver 8.8.8.8\n"); got != "10.0.0.2:53" {
		t.Fatalf("got %q", got)
	}
	if got := UpstreamFromResolvConf("nameserver fd00::2\n"); got != "[fd00::2]:53" {
		t.Fatalf("v6 = %q", got)
	}
}
