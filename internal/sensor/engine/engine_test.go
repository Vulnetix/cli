package engine

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
)

func rule(uuid, typ, body string) feed.Rule {
	return feed.Rule{RuleTable: "virtual_patch", RuleUUID: uuid, RuleType: typ, DeployMode: "block", Body: body}
}

func statuses(results []Result) map[string]Result {
	out := map[string]Result{}
	for _, r := range results {
		out[r.Rule.RuleUUID] = r
	}

	return out
}

func TestCompileReportsEveryRule(t *testing.T) {
	set, results := Compile([]feed.Rule{
		rule("traversal", "MODSECURITY", `SecRule ARGS "@contains ../" "id:910001,phase:2,deny,msg:'path traversal'"`),
		rule("broken", "MODSECURITY", `SecRule ARGS "@nosuchoperator x" "id:910002,deny"`),
		rule("noid", "MODSECURITY", `SecRule ARGS "@contains x" "phase:2,deny"`),
		rule("clash", "MODSECURITY", `SecRule ARGS "@contains y" "id:910001,phase:2,deny"`),
		rule("regex", "REGEX_L7", "# log4shell\n/\\$\\{jndi:/i"),
		rule("lookahead", "REGEX_L7", "(?=x)y"),
		rule("snort", "SNORT", `alert tcp any any -> any 80 (sid:1;)`),
		{RuleTable: "virtual_patch", RuleUUID: "off", RuleType: "MODSECURITY", Disabled: true, Body: "x"},
	})
	got := statuses(results)
	want := map[string]string{
		"traversal": Compiled, "broken": Rejected, "noid": Rejected, "clash": Rejected,
		"regex": Compiled, "lookahead": Rejected, "snort": NoEngine, "off": Rejected,
	}
	for id, status := range want {
		if got[id].Status != status {
			t.Errorf("%s: %s (%s), want %s", id, got[id].Status, got[id].Reason, status)
		}
	}
	if !strings.Contains(got["lookahead"].Reason, "RE2") {
		t.Errorf("a PCRE-only pattern must say why: %q", got["lookahead"].Reason)
	}
	if set.modsec == nil || len(set.regex) != 1 {
		t.Fatal("compiled rules did not make it into the set")
	}
}

func TestInspectRequestAttributesHitsToRules(t *testing.T) {
	set, _ := Compile([]feed.Rule{
		rule("traversal", "MODSECURITY", `SecRule ARGS "@contains ../" "id:910001,phase:2,deny,msg:'path traversal'"`),
		rule("log4shell", "REGEX_L7", `/\$\{jndi:/i`),
	})

	r := httptest.NewRequest("GET", "/download?file=../../etc/passwd", nil)
	hits := set.InspectRequest(r, nil)
	if len(hits) != 1 || hits[0].Rule.UUID != "traversal" {
		t.Fatalf("hits = %+v", hits)
	}

	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Api-Version", "${JNDI:ldap://x/a}")
	hits = set.InspectRequest(r, nil)
	if len(hits) != 1 || hits[0].Rule.UUID != "log4shell" {
		t.Fatalf("header hit = %+v", hits)
	}

	if hits := set.InspectRequest(httptest.NewRequest("GET", "/ok", nil), nil); len(hits) != 0 {
		t.Fatalf("a clean request matched: %+v", hits)
	}
}

func TestIOCSets(t *testing.T) {
	stix := `{"type":"bundle","objects":[
		{"type":"indicator","pattern":"[domain-name:value = 'evil.example'] OR [ipv4-addr:value = '203.0.113.9']"},
		{"type":"indicator","pattern":"[file:hashes.'SHA-256' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']"},
		{"type":"indicator","pattern":"[url:value = 'https://user@cdn.bad.example:8443/x']"},
		{"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.0/24']"}
	]}`
	openioc := `<ioc><definition><Indicator>
		<IndicatorItem><Context search="DnsEntryItem/Host"/><Content>c2.other.example</Content></IndicatorItem>
		<IndicatorItem><Context search="FileItem/Md5sum"/><Content>0123456789abcdef0123456789abcdef</Content></IndicatorItem>
	</Indicator></definition></ioc>`
	set, results := Compile([]feed.Rule{
		{RuleTable: "countermeasure", RuleUUID: "stix", RuleType: "STIX", Body: stix},
		{RuleTable: "countermeasure", RuleUUID: "openioc", RuleType: "OPENIOC", Body: openioc},
		{RuleTable: "countermeasure", RuleUUID: "empty", RuleType: "STIX", Body: `{"type":"bundle","objects":[]}`},
	})
	if s := statuses(results); s["stix"].Status != Compiled || s["openioc"].Status != Compiled || s["empty"].Status != Rejected {
		t.Fatalf("results = %+v", results)
	}

	for host, want := range map[string]string{
		"evil.example": "stix", "a.b.EVIL.example.": "stix", "203.0.113.9:443": "stix",
		"cdn.bad.example": "stix", "c2.other.example": "openioc",
	} {
		r, _, ok := set.IOC.MatchHost(host)
		if !ok || r.UUID != want {
			t.Errorf("MatchHost(%q) = %v %v, want %s", host, r, ok, want)
		}
	}
	for _, host := range []string{"notevil.example", "example", "198.51.100.7"} {
		if _, _, ok := set.IOC.MatchHost(host); ok {
			t.Errorf("MatchHost(%q) matched", host)
		}
	}
	if r, ok := set.IOC.MatchHash(strings.ToUpper("0123456789abcdef0123456789abcdef")); !ok || r != (decide.RuleRef{Table: "countermeasure", UUID: "openioc"}) {
		t.Fatal("hash lookup must be case-insensitive")
	}
}
