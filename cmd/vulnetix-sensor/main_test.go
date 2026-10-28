package main

import (
	"strings"
	"testing"
)

func TestRunRefusesAnIncompleteConfiguration(t *testing.T) {
	cases := map[string]struct {
		args []string
		want string
	}{
		"mode":      {[]string{"--mode", "kill", "--feed", "https://x/f", "--listen", ":1"}, "--mode"},
		"no feed":   {[]string{"--listen", ":1", "--upstream", "http://127.0.0.1:2"}, "--feed"},
		"no target": {[]string{"--feed", "https://x/f"}, "--listen"},
		"bad key":   {[]string{"--feed", "https://x/f", "--egress-listen", ":3", "--feed-key", "short"}, "feed key"},
		"upstream":  {[]string{"--feed", "https://x/f", "--listen", ":1", "--upstream", "not-a-url", "--offline", "--state-dir", t.TempDir()}, "--upstream"},
	}
	for name, c := range cases {
		err := run(c.args)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, c.want)
		}
	}
}

func TestVersion(t *testing.T) {
	if err := run([]string{"--version"}); err != nil {
		t.Fatal(err)
	}
}
