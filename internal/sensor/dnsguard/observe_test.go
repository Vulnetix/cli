package dnsguard

import (
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/engine"
	"github.com/vulnetix/cli/v3/internal/sensor/siem"
)

type observed struct {
	mu  sync.Mutex
	all []siem.DNSDecision
}

func (o *observed) add(d siem.DNSDecision) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.all = append(o.all, d)
}

// Every lookup is observed, not only the ones an indicator names: the SIEM
// needs the clean traffic to see what a compromise looks like beside it.
func TestEveryLookupIsObserved(t *testing.T) {
	g, _ := guard(t, decide.Enforce)
	obs := &observed{}
	g.Observe = obs.add

	g.answer(query(t, "C2.Evil.Example."), "10.0.0.5:5353")
	g.answer(query(t, "example.com."), "10.0.0.5:5354")

	if len(obs.all) != 2 {
		t.Fatalf("observed %d lookups, want 2", len(obs.all))
	}
	refused := obs.all[0]
	if refused.RCode != "NXDOMAIN" || refused.QType != "A" || refused.Client != "10.0.0.5:5353" {
		t.Fatalf("refused lookup = %+v", refused)
	}
	if refused.Match == nil || refused.Match.Verdict.Action != decide.Blocked || refused.Match.Rule.UUID != "cm" {
		t.Fatalf("refused lookup carries its rule and verdict: %+v", refused.Match)
	}
	clean := obs.all[1]
	if clean.RCode != "NOERROR" || clean.Match != nil || clean.QName != "example.com" {
		t.Fatalf("clean lookup = %+v", clean)
	}
}

func TestObservedWithNoRulesLoaded(t *testing.T) {
	obs := &observed{}
	g := &Guard{Upstream: fakeResolver(t), Rules: func() *engine.Set { return nil }, Observe: obs.add}
	if g.Answer(query(t, "example.com.")) == nil {
		t.Fatal("no rules still answers")
	}
	if len(obs.all) != 1 || obs.all[0].Match != nil || obs.all[0].RCode != "NOERROR" {
		t.Fatalf("observed = %+v", obs.all)
	}
}

func TestUpstreamFailureIsObservedWithTheError(t *testing.T) {
	obs := &observed{}
	g := &Guard{Upstream: "", Rules: func() *engine.Set { return nil }, Observe: obs.add}
	if g.Answer(query(t, "example.com.")) != nil {
		t.Fatal("no upstream, no reply")
	}
	if len(obs.all) != 1 || obs.all[0].Error == "" || obs.all[0].RCode != "" {
		t.Fatalf("observed = %+v", obs.all)
	}
}

func TestAPanickingObserverCostsOnlyTheCopy(t *testing.T) {
	g, _ := guard(t, decide.Enforce)
	g.Observe = func(siem.DNSDecision) { panic("boom") }
	if rc := rcode(t, g.Answer(query(t, "evil.example."))); rc != dnsmessage.RCodeNameError {
		t.Fatalf("rcode = %v", rc)
	}
}

func TestParseReplyReadsAnswers(t *testing.T) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, Response: true})
	_ = b.StartQuestions()
	name := dnsmessage.MustNewName("www.example.com.")
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	hdr := dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 60}
	_ = b.CNAMEResource(hdr, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("edge.example.net.")})
	_ = b.AResource(hdr, dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}})
	_ = b.TXTResource(hdr, dnsmessage.TXTResource{TXT: []string{"skipped"}})
	_ = b.AAAAResource(hdr, dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}})
	reply, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	rc, answers := parseReply(reply)
	want := []string{"edge.example.net", "93.184.216.34", "2001:db8::1"}
	if rc != "NOERROR" || len(answers) != len(want) {
		t.Fatalf("rcode %q answers %v", rc, answers)
	}
	for i := range want {
		if answers[i] != want[i] {
			t.Fatalf("answers = %v, want %v", answers, want)
		}
	}
	if rc, _ := parseReply([]byte{1}); rc != "" {
		t.Fatal("garbage has no rcode")
	}
}
