package engine

import (
	"testing"

	"github.com/vulnetix/cli/v3/internal/sensor/feed"
)

func yaraRuleEntry(uuid, body string) feed.Rule {
	return feed.Rule{RuleTable: "countermeasure", RuleUUID: uuid, RuleType: "YARA", DeployMode: "log", Body: body}
}

const minerYara = `
rule XMRig_Miner : miner
{
    meta:
        description = "XMRig CPU miner"
    strings:
        $pool = "stratum+tcp://" nocase
        $name = "xmrig" fullword
        $cfg  = { 22 64 6F 6E 61 74 65 2D 6C 65 76 65 6C 22 }  // "donate-level"
        $w    = "XMRIG" wide
        $re   = /--(cpu|max)-threads/
    condition:
        uint32(0) == 0x464c457f and filesize < 10MB and ($pool or 2 of ($name, $cfg, $re))
}`

func TestYaraMatchesTheSupportedSubset(t *testing.T) {
	set, results := Compile([]feed.Rule{yaraRuleEntry("miner", minerYara)})
	if results[0].Status != Compiled {
		t.Fatalf("result = %+v", results[0])
	}
	elf := "\x7fELF\x02\x01\x01"
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"pool", elf + " connect STRATUM+TCP://pool.example:3333", true},
		{"two of the set", elf + ` run xmrig "donate-level":1`, true},
		{"fullword", elf + ` run xmrigx "donate-level":1`, false},
		{"regex and hex", elf + ` --max-threads "donate-level"`, true},
		{"not an ELF", "MZ stratum+tcp://x", false},
		{"one of the set only", elf + " xmrig", false},
	}
	for _, c := range cases {
		if got := len(set.MatchFile([]byte(c.data))) == 1; got != c.want {
			t.Errorf("%s: matched %v, want %v", c.name, got, c.want)
		}
	}
}

func TestYaraWideAndHexJumps(t *testing.T) {
	set, results := Compile([]feed.Rule{yaraRuleEntry("w", `rule W { strings: $a = "ab" wide $h = { 4D 5A [2-4] 90 ?? ( 01 | 02 ) } condition: all of them }`)})
	if results[0].Status != Compiled {
		t.Fatalf("result = %+v", results[0])
	}
	if len(set.MatchFile([]byte("a\x00b\x00 MZ\x00\x00\x00\x90\xff\x02"))) != 1 {
		t.Fatal("wide string and hex with a jump, wildcard and alternation should match")
	}
	if len(set.MatchFile([]byte("ab MZ\x00\x90\xff\x02"))) != 0 {
		t.Fatal("narrow text is not a wide string, and a 1-byte gap is outside [2-4]")
	}
}

func TestYaraRejectsWhatItCannotEvaluate(t *testing.T) {
	_, results := Compile([]feed.Rule{
		yaraRuleEntry("pe", "import \"pe\"\nrule A { condition: pe.number_of_sections > 2 }"),
		yaraRuleEntry("count", `rule A { strings: $a = "x" condition: #a > 3 }`),
		yaraRuleEntry("at", `rule A { strings: $a = "x" condition: $a at 0 }`),
		yaraRuleEntry("for", `rule A { strings: $a = "x" condition: for any i in (1..2): ($a) }`),
		yaraRuleEntry("xor", `rule A { strings: $a = "x" xor condition: $a }`),
		yaraRuleEntry("two", "rule A { condition: true }\nrule B { condition: true }"),
		yaraRuleEntry("undefined", `rule A { strings: $a = "x" condition: $b }`),
		yaraRuleEntry("nibble", `rule A { strings: $a = { 4? 5A } condition: $a }`),
		yaraRuleEntry("lookahead", `rule A { strings: $a = /a(?=b)/ condition: $a }`),
	})
	for _, r := range results {
		if r.Status != Rejected || r.Reason == "" {
			t.Errorf("%s: %+v, want rejected with a reason", r.Rule.RuleUUID, r)
		}
	}
}
