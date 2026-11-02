package engine

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
)

const sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func iocList(body string) feed.Rule {
	return feed.Rule{RuleTable: "ioc", RuleUUID: "list-1", RuleType: "IOC_LIST", Name: "catalog:x", DeployMode: "log", Body: body}
}

func TestIOCListParsesEveryKind(t *testing.T) {
	body := strings.Join([]string{
		"# vulnetix indicators v1",
		"# feed catalog:x",
		"",
		"d Evil-Domain.TOP.",
		"i 185.220.101.9",
		"i 2001:DB8::0001",
		"u https://user@phish-login.top:8443/a?b#c",
		"u http://198.51.100.7/x",
		"h " + strings.ToUpper(sha),
		"  d spaced.example  ",
		"# d commented.example",
		"x unknown.example",   // unknown kind
		"dnokind.example",     // no separator
		"i not-an-ip",         // bad address
		"h deadbeef",          // not a SHA-256
		"d two words.example", // a domain has no spaces
		"d",
		"d ",
	}, "\r\n")
	set, results := Compile([]feed.Rule{iocList(body)})
	if len(results) != 1 || results[0].Status != Compiled {
		t.Fatalf("results = %+v", results)
	}
	want := decide.RuleRef{Table: "ioc", UUID: "list-1"}
	for _, d := range []string{"evil-domain.top", "phish-login.top", "spaced.example"} {
		if r, ok := set.IOC.Domains[d]; !ok || r != want {
			t.Errorf("domain %s missing", d)
		}
	}
	for _, ip := range []string{"185.220.101.9", "2001:db8::1", "198.51.100.7"} {
		if _, ok := set.IOC.IPs[ip]; !ok {
			t.Errorf("ip %s missing", ip)
		}
	}
	if _, ok := set.IOC.Hashes[sha]; !ok {
		t.Error("hash missing")
	}
	if n := set.IOC.Len(); n != 7 {
		t.Fatalf("indicators = %d (%v %v %v)", n, set.IOC.Domains, set.IOC.IPs, set.IOC.Hashes)
	}
	if _, _, ok := set.IOC.MatchHost("c2.evil-domain.top"); !ok {
		t.Error("a subdomain of a listed domain matches")
	}
	if !set.HasProcessRules() {
		t.Error("a hash indicator turns process checks on")
	}
}

func TestIOCListWithNoIndicatorsIsRejected(t *testing.T) {
	_, results := Compile([]feed.Rule{iocList("# vulnetix indicators v1\n# etag x\nzz nothing\n")})
	if len(results) != 1 || results[0].Status != Rejected || results[0].Reason != "no domain, IP or file hash indicators the sensor can match" {
		t.Fatalf("results = %+v", results)
	}
}

// TestIOCListMemory loads a 150,000-domain list, the size of the larger
// public blocklists, and reports what the compiled set costs on the heap.
func TestIOCListMemory(t *testing.T) {
	const n = 150_000
	var b strings.Builder
	b.WriteString("# vulnetix indicators v1\n# feed catalog:big\n")
	for i := range n {
		fmt.Fprintf(&b, "d host-%06d.bad-domain-%d.example\n", i, i%97)
	}
	body := b.String()

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	set, results := Compile([]feed.Rule{iocList(body)})
	runtime.GC()
	runtime.ReadMemStats(&after)

	if results[0].Status != Compiled || len(set.IOC.Domains) != n {
		t.Fatalf("status %s, %d domains", results[0].Status, len(set.IOC.Domains))
	}
	if _, _, ok := set.IOC.MatchHost(fmt.Sprintf("c2.host-%06d.bad-domain-%d.example", n-1, (n-1)%97)); !ok {
		t.Fatal("last domain not matched")
	}
	grew := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("150,000-domain IOC_LIST: body %.1f MiB, compiled set adds %.1f MiB of heap (%.0f bytes/indicator)",
		float64(len(body))/(1<<20), float64(grew)/(1<<20), float64(grew)/n)
	// Map entries (a key header and the 32-byte rule ref) dominate; keys
	// point into the body. Well over this means per-line copies came back.
	if grew > 40<<20 {
		t.Fatalf("compiled set costs %d bytes of heap for %d domains", grew, n)
	}
	runtime.KeepAlive(set)
	runtime.KeepAlive(body)
}
