package engine

import (
	"testing"

	"github.com/vulnetix/cli/v3/internal/sensor/feed"
)

const minerRule = `
title: Process started from a temporary directory with a pool argument
logsource:
  product: linux
  category: process_creation
detection:
  selection_dir:
    Image|startswith:
      - /tmp/
      - /dev/shm/
  selection_args:
    CommandLine|contains|all:
      - '--pool'
      - 'stratum'
  filter_known:
    ParentImage|endswith: '/usr/bin/apt'
  condition: 1 of selection_* and not filter_known
`

func sigma(uuid, body string) feed.Rule {
	return feed.Rule{RuleTable: "countermeasure", RuleUUID: uuid, RuleType: "SIGMA", DeployMode: "log", Body: body}
}

func TestSigmaProcessCreation(t *testing.T) {
	set, results := Compile([]feed.Rule{sigma("miner", minerRule)})
	if results[0].Status != Compiled {
		t.Fatalf("result = %+v", results[0])
	}

	cases := []struct {
		name string
		p    Process
		want bool
	}{
		{"temp dir", Process{Image: "/tmp/.x/kworker", CommandLine: "kworker"}, true},
		{"args all present", Process{Image: "/usr/bin/xmrig", CommandLine: "xmrig --POOL stratum+tcp://p:3333"}, true},
		{"only one arg", Process{Image: "/usr/bin/xmrig", CommandLine: "xmrig --pool x"}, false},
		{"filtered parent", Process{Image: "/tmp/apt-helper", ParentImage: "/usr/bin/apt"}, false},
		{"clean", Process{Image: "/usr/bin/ls", CommandLine: "ls -la"}, false},
	}
	for _, c := range cases {
		if got := len(set.MatchProcess(c.p)) == 1; got != c.want {
			t.Errorf("%s: matched %v, want %v", c.name, got, c.want)
		}
	}
	if !set.HasProcessRules() {
		t.Fatal("a Sigma rule is a process rule")
	}
}

func TestSigmaRefusesWhatItCannotEvaluate(t *testing.T) {
	_, results := Compile([]feed.Rule{
		sigma("net", "title: x\nlogsource: {category: network_connection}\ndetection: {sel: {DestinationPort: 4444}, condition: sel}\n"),
		sigma("field", "title: x\nlogsource: {category: process_creation}\ndetection: {sel: {Hashes|contains: abc}, condition: sel}\n"),
		sigma("mod", "title: x\nlogsource: {category: process_creation}\ndetection: {sel: {Image|base64offset|contains: abc}, condition: sel}\n"),
		sigma("agg", "title: x\nlogsource: {category: process_creation}\ndetection: {sel: {Image: x}, condition: sel | count() > 5}\n"),
		sigma("kw", "title: x\nlogsource: {category: process_creation}\ndetection: {keywords: [evil], condition: keywords}\n"),
		sigma("cond", "title: x\nlogsource: {category: process_creation}\ndetection: {sel: {Image: x}, condition: sel and other}\n"),
		sigma("ok", "title: x\nlogsource: {category: process_creation}\ndetection: {sel: {Image: '*/nc'}, condition: all of them}\n"),
	})
	got := statuses(results)
	for _, id := range []string{"net", "field", "mod", "agg", "kw", "cond"} {
		if got[id].Status != Rejected || got[id].Reason == "" {
			t.Errorf("%s: %+v, want rejected with a reason", id, got[id])
		}
	}
	if got["ok"].Status != Compiled {
		t.Errorf("wildcard rule: %+v", got["ok"])
	}
}
