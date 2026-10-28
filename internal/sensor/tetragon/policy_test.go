package tetragon

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vulnetix/cli/v3/internal/sensor/feed"
)

func sigma(uuid, mode, body string) feed.Rule {
	return feed.Rule{RuleTable: "countermeasure", RuleUUID: uuid, RuleType: "SIGMA", DeployMode: mode, Body: body}
}

func TestRenderTakesOnlyImageRulesInBlockMode(t *testing.T) {
	got, err := Render([]feed.Loaded{{Verified: true, Rules: []feed.Rule{
		sigma("tmp", "block", "logsource: {category: process_creation}\ndetection: {sel: {Image|startswith: [/tmp/, /dev/shm/]}, condition: sel}\n"),
		sigma("nc", "block", "logsource: {category: process_creation}\ndetection: {sel: {Image|endswith: /nc}, condition: sel}\n"),
		sigma("log", "log", "logsource: {category: process_creation}\ndetection: {sel: {Image: /bin/x}, condition: sel}\n"),
		sigma("cmd", "block", "logsource: {category: process_creation}\ndetection: {sel: {CommandLine|contains: stratum}, condition: sel}\n"),
		sigma("two", "block", "logsource: {category: process_creation}\ndetection: {a: {Image: /x}, b: {Image: /y}, condition: a or b}\n"),
		sigma("glob", "block", "logsource: {category: process_creation}\ndetection: {sel: {Image: /tmp/*}, condition: sel}\n"),
	}}, {Verified: false, Rules: []feed.Rule{
		sigma("unsigned", "block", "logsource: {category: process_creation}\ndetection: {sel: {Image: /z}, condition: sel}\n"),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Used, ",") != "tmp,nc" {
		t.Fatalf("used = %v", got.Used)
	}
	if len(got.Skipped) != 5 {
		t.Fatalf("skipped = %+v", got.Skipped)
	}

	var policy struct {
		Kind string
		Spec struct {
			Kprobes []struct {
				Call      string
				Selectors []struct {
					MatchArgs []struct {
						Operator string
						Values   []string
					} `yaml:"matchArgs"`
					MatchActions []struct {
						Action   string
						ArgError int `yaml:"argError"`
					} `yaml:"matchActions"`
				}
			}
		}
	}
	if err := yaml.Unmarshal(got.YAML, &policy); err != nil {
		t.Fatal(err)
	}
	k := policy.Spec.Kprobes[0]
	if policy.Kind != "TracingPolicy" || k.Call != Hook || len(k.Selectors) != 2 {
		t.Fatalf("policy = %+v", policy)
	}
	if k.Selectors[0].MatchArgs[0].Operator != "Prefix" || strings.Join(k.Selectors[0].MatchArgs[0].Values, ",") != "/dev/shm/,/tmp/" ||
		k.Selectors[1].MatchArgs[0].Operator != "Postfix" || k.Selectors[1].MatchActions[0].Action != "Override" || k.Selectors[1].MatchActions[0].ArgError != -1 {
		t.Fatalf("selectors = %+v", k.Selectors)
	}
}

func TestRenderRefusesWhenNothingFits(t *testing.T) {
	if _, err := Render([]feed.Loaded{{Verified: true}}); err == nil {
		t.Fatal("an empty policy would apply and block nothing; it should be an error")
	}
}

func TestExactImagesTakesOnlyExactPaths(t *testing.T) {
	got := ExactImages([]feed.Rule{
		sigma("a", "block", "logsource: {category: process_creation}\ndetection: {sel: {Image: [/usr/bin/nc, /usr/bin/ncat]}, condition: sel}\n"),
		sigma("b", "block", "logsource: {category: process_creation}\ndetection: {sel: {Image|startswith: /tmp/}, condition: sel}\n"),
		sigma("c", "block", "logsource: {category: process_creation}\ndetection: {sel: {Image: /usr/bin/nc}, condition: sel}\n"),
	})
	if len(got) != 2 || got["/usr/bin/nc"].RuleUUID != "a" || got["/usr/bin/ncat"].RuleUUID != "a" {
		t.Fatalf("got %+v", got)
	}
}
