package agent

import (
	"testing"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
)

func TestLSMEntriesFollowTheEffectiveMode(t *testing.T) {
	image := func(uuid, path string) feed.Rule {
		return feed.Rule{RuleTable: "countermeasure", RuleUUID: uuid, RuleType: "SIGMA", DeployMode: "block",
			Body: "logsource: {category: process_creation}\ndetection: {sel: {Image: " + path + "}, condition: sel}\n"}
	}
	rules := []feed.Rule{image("blocked", "/usr/bin/nc"), image("demoted", "/usr/bin/socat"), image("unsigned", "/usr/bin/xmrig")}
	off := image("off", "/usr/bin/curl")
	off.Disabled = true
	rules = append(rules, off)

	v := decide.New(decide.Enforce, decide.Config{})
	ref := func(u string) decide.RuleRef { return decide.RuleRef{Table: "countermeasure", UUID: u} }
	v.SetRules([]decide.Rule{
		{Ref: ref("blocked"), Mode: decide.Block, Verified: true},
		{Ref: ref("demoted"), Mode: decide.Log, Verified: true},
		{Ref: ref("unsigned"), Mode: decide.Block, Verified: false},
		{Ref: ref("off"), Mode: decide.Block, Verified: true},
	})
	got := lsmEntries(rules, v)
	if len(got) != 1 || got[0].Path != "/usr/bin/nc" || got[0].Rule.UUID != "blocked" {
		t.Fatalf("entries = %+v", got)
	}
}
