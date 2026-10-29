package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

// The deploy files are copied into customers' accounts. A flag they pass that
// the binary does not define fails the sensor at start-up, so every --flag in
// them must be one run() accepts, and the YAML and JSON must parse.
func TestDeployFilesUseRealFlags(t *testing.T) {
	known := map[string]bool{}
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	defineFlags(fs)
	fs.VisitAll(func(f *flag.Flag) { known[f.Name] = true })

	flagToken := regexp.MustCompile(`--([a-z][a-z-]+)`)
	for _, name := range []string{"install.sh", "ssm-document.yaml", "ecs-sidecar.json", "kubernetes-sidecar.yaml", "kubernetes-node-daemonset.yaml", "README.md"} {
		body, err := os.ReadFile(filepath.Join("..", "..", "deploy", "sensor", name))
		if err != nil {
			t.Fatal(err)
		}
		switch filepath.Ext(name) {
		case ".yaml":
			dec := yaml.NewDecoder(strings.NewReader(string(body)))
			for {
				var doc map[string]any
				if err := dec.Decode(&doc); err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					t.Fatalf("%s does not parse: %v", name, err)
				}
			}
		case ".json":
			var doc map[string]any
			if err := json.Unmarshal(body, &doc); err != nil {
				t.Fatalf("%s does not parse: %v", name, err)
			}
		}
		for _, m := range flagToken.FindAllStringSubmatch(string(body), -1) {
			flagName := m[1]
			if notSensorFlag[flagName] {
				continue
			}
			if !known[flagName] {
				t.Errorf("%s passes --%s, which vulnetix-sensor does not define", name, flagName)
			}
		}
	}
}

// Flags in the deploy files that belong to other commands (aws, docker,
// kubectl, curl, systemd), not the sensor.
var notSensorFlag = map[string]bool{
	"name": true, "document-type": true, "document-format": true, "content": true,
	"secret-id": true, "query": true, "output": true, "build-arg": true,
	"from-literal": true, "now": true, "trimpath": true, "ldflags": true,
}

func TestVersion(t *testing.T) {
	if err := run([]string{"--version"}); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultFeedKeyPrefersTheEnvironment(t *testing.T) {
	pinnedFeedKey = "pinned"
	defer func() { pinnedFeedKey = "" }()
	t.Setenv("VULNETIX_FEED_KEY", "")
	if defaultFeedKey() != "pinned" {
		t.Fatal("with no environment key, the build's pinned key is used")
	}
	t.Setenv("VULNETIX_FEED_KEY", " rotated ")
	if defaultFeedKey() != "rotated" {
		t.Fatal("an environment key overrides the pinned one, for rotation")
	}
}

func TestForwardSIEMNeedsAToken(t *testing.T) {
	t.Setenv("VULNETIX_SIEM_TOKEN", "")
	err := run([]string{"--feed", "https://x/f", "--dns-listen", "127.0.0.1:0", "--offline", "--state-dir", t.TempDir(), "--forward", "siem"})
	if err == nil || !strings.Contains(err.Error(), "--siem-token") || !strings.Contains(err.Error(), "VULNETIX_SIEM_TOKEN") {
		t.Fatalf("err = %v, want it to name --siem-token and VULNETIX_SIEM_TOKEN", err)
	}
}

func TestSIEMForwarderFlags(t *testing.T) {
	parse := func(args ...string) *options {
		fs := flag.NewFlagSet("probe", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		o := defineFlags(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}

		return o
	}
	t.Setenv("VULNETIX_SIEM_TOKEN", "")
	t.Setenv("VULNETIX_SIEM_URL", "")

	if f, err := siemForwarder(parse("--egress-listen", ":3128")); f != nil || err != nil {
		t.Fatalf("no --forward forwards nothing: %v %v", f, err)
	}
	if _, err := siemForwarder(parse("--forward", "splunk", "--egress-listen", ":3128")); err == nil || !strings.Contains(err.Error(), "siem") {
		t.Fatalf("an unknown destination is refused: %v", err)
	}
	if _, err := siemForwarder(parse("--forward", "siem", "--siem-token", "gdn_x", "--tetragon-export", "x")); err == nil || !strings.Contains(err.Error(), "--dns-listen") {
		t.Fatalf("nothing to forward without DNS or egress: %v", err)
	}
	if _, err := siemForwarder(parse("--forward", "siem", "--siem-token", "gdn_x", "--dns-listen", ":53", "--siem-url", "http://guardian.example/v1/ingest/events")); err == nil {
		t.Fatal("the token is never sent over plain http off the machine")
	}

	f, err := siemForwarder(parse("--forward", "siem", "--siem-token", "gdn_flag", "--dns-listen", ":53"))
	if err != nil || f.Token != "gdn_flag" || f.URL != "https://ingest.vulnetix.com/v1/ingest/events" {
		t.Fatalf("flag token = %+v %v", f, err)
	}

	t.Setenv("VULNETIX_SIEM_TOKEN", "gdn_env")
	t.Setenv("VULNETIX_SIEM_URL", "http://127.0.0.1:8787/v1/ingest/events")
	f, err = siemForwarder(parse("--forward", "siem", "--egress-listen", ":3128"))
	if err != nil || f.Token != "gdn_env" || f.URL != "http://127.0.0.1:8787/v1/ingest/events" {
		t.Fatalf("environment = %+v %v", f, err)
	}
}
