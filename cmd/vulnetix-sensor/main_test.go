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
	for _, name := range []string{"install.sh", "ssm-document.yaml", "ecs-sidecar.json", "kubernetes-sidecar.yaml", "README.md"} {
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
