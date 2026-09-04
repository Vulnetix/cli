package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdvisoryIDsIn(t *testing.T) {
	cases := []struct {
		name   string
		prompt string
		want   []string
	}{
		{"none", "refactor the parser", nil},
		{"empty", "", nil},
		{"one cve", "does CVE-2021-44228 affect us?", []string{"CVE-2021-44228"}},
		{"five digit cve", "CVE-2024-123456", []string{"CVE-2024-123456"}},
		{"ghsa", "look at GHSA-jfh8-c2jp-5v3q", []string{"GHSA-jfh8-c2jp-5v3q"}},

		// Case is preserved as written: the two schemes have opposite
		// conventions and normalising picks the wrong one for one of them.
		{"case preserved", "cve-2021-44228", []string{"cve-2021-44228"}},

		{
			"deduped across case",
			"CVE-2021-44228 and cve-2021-44228 again",
			[]string{"CVE-2021-44228"},
		},
		{
			"two",
			"CVE-2021-44228 plus GHSA-jfh8-c2jp-5v3q",
			[]string{"CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"},
		},

		// A prompt naming a dozen advisories is pasting a report. Answering all
		// of them would bury the prompt they were attached to.
		{
			"capped",
			"CVE-2020-0001 CVE-2020-0002 CVE-2020-0003 CVE-2020-0004 CVE-2020-0005 CVE-2020-0006",
			[]string{"CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0004", "CVE-2020-0005"},
		},

		// Things that must not be mistaken for an identifier.
		{"too few digits", "CVE-2021-1", nil},
		{"bare word", "the cve database", nil},
		{"ghsa too short", "GHSA-abc-def-ghi", nil},
		{"not a boundary", "XCVE-2021-44228X", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := advisoryIDsIn(tc.prompt)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// memoryRepo writes a .vulnetix/memory.yaml and returns the repository root.
func memoryRepo(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".vulnetix")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

const memoryWithLog4Shell = `version: "1"
last_scan:
  timestamp: "2026-09-04T04:34:38Z"
  git_branch: main
  files_scanned: 12
  packages: 255
  vulns: 3
  critical: 2
  high: 1
findings:
  CVE-2021-44228:
    package: org.apache.logging.log4j:log4j-core
    ecosystem: maven
    severity: critical
    status: affected
    in_cisa_kev: true
    aliases: ["GHSA-jfh8-c2jp-5v3q"]
    versions:
      current: 2.14.1
      fixed_in: 2.17.1
  CVE-2020-8203:
    package: lodash
    ecosystem: npm
    severity: high
`

func TestSessionStart_SummarisesTheRecordedScan(t *testing.T) {
	root := memoryRepo(t, memoryWithLog4Shell)

	got := Runner{Policy: DefaultPolicy(), Root: root}.
		Run(context.Background(), Payload{HookEventName: EventSessionStart})

	if got.Decision != Inform {
		t.Fatalf("decision = %v, want Inform", got.Decision)
	}
	for _, want := range []string{"255 packages", "3 vulnerabilities", "2 critical, 1 high", "CVE-2021-44228"} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("message should contain %q:\n%s", want, got.Message)
		}
	}
	// It must not read as a scan that just ran.
	if !strings.Contains(got.Message, "recorded snapshot") {
		t.Errorf("message should say it is a snapshot:\n%s", got.Message)
	}
}

func TestSessionStart_SaysWhenThereIsNoScan(t *testing.T) {
	got := Runner{Policy: DefaultPolicy(), Root: t.TempDir()}.
		Run(context.Background(), Payload{HookEventName: EventSessionStart})

	if got.Decision != Inform {
		t.Fatalf("decision = %v, want Inform", got.Decision)
	}
	if !strings.Contains(got.Message, "no scan on record") {
		t.Errorf("unexpected message:\n%s", got.Message)
	}
}

func TestUserPromptSubmit_AnswersFromTheRepoRecord(t *testing.T) {
	root := memoryRepo(t, memoryWithLog4Shell)
	r := Runner{Policy: DefaultPolicy(), Root: root}

	got := r.Run(context.Background(), Payload{
		HookEventName: EventUserPromptSubmit,
		Prompt:        "does CVE-2021-44228 affect us?",
	})

	if got.Decision != Inform {
		t.Fatalf("decision = %v, want Inform", got.Decision)
	}
	for _, want := range []string{"log4j-core@2.14.1", "critical", "known exploited", "fixed in 2.17.1"} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("message should contain %q:\n%s", want, got.Message)
		}
	}
}

// The same advisory under the identifier the person happened to read.
func TestUserPromptSubmit_ResolvesAnAlias(t *testing.T) {
	root := memoryRepo(t, memoryWithLog4Shell)

	got := Runner{Policy: DefaultPolicy(), Root: root}.
		Run(context.Background(), Payload{
			HookEventName: EventUserPromptSubmit,
			Prompt:        "what about GHSA-jfh8-c2jp-5v3q",
		})

	if !strings.Contains(got.Message, "log4j-core") {
		t.Fatalf("an alias should resolve to the same finding:\n%s", got.Message)
	}
}

// "Not in the last scan" is an answer. Saying nothing would read as "not
// affected", which is a different and much stronger claim.
func TestUserPromptSubmit_SaysWhenAnAdvisoryIsAbsent(t *testing.T) {
	root := memoryRepo(t, memoryWithLog4Shell)

	got := Runner{Policy: DefaultPolicy(), Root: root}.
		Run(context.Background(), Payload{
			HookEventName: EventUserPromptSubmit,
			Prompt:        "is CVE-1999-0001 a problem here?",
		})

	if got.Decision != Inform {
		t.Fatalf("decision = %v, want Inform", got.Decision)
	}
	if !strings.Contains(got.Message, "not in this repository's last scan") {
		t.Errorf("unexpected message:\n%s", got.Message)
	}
}

// The overwhelmingly common prompt. It must cost nothing and say nothing.
func TestUserPromptSubmit_SilentWithoutAnAdvisory(t *testing.T) {
	root := memoryRepo(t, memoryWithLog4Shell)

	got := Runner{Policy: DefaultPolicy(), Root: root}.
		Run(context.Background(), Payload{
			HookEventName: EventUserPromptSubmit,
			Prompt:        "refactor the parser to use a table",
		})

	if got.Decision != Silent {
		t.Fatalf("decision = %v, want Silent\nmessage: %s", got.Decision, got.Message)
	}
}

// A repository with no scan cannot answer, and must not invent one.
func TestUserPromptSubmit_SilentWithoutAScan(t *testing.T) {
	got := Runner{Policy: DefaultPolicy(), Root: t.TempDir()}.
		Run(context.Background(), Payload{
			HookEventName: EventUserPromptSubmit,
			Prompt:        "does CVE-2021-44228 affect us?",
		})

	if got.Decision != Silent {
		t.Fatalf("decision = %v, want Silent\nmessage: %s", got.Decision, got.Message)
	}
}

// The whole surface has an off switch, and it has to reach these events too.
func TestSessionContext_RespectsTheOffSwitch(t *testing.T) {
	root := memoryRepo(t, memoryWithLog4Shell)

	off := false
	p := DefaultPolicy()
	p.Enabled = &off

	for _, ev := range []Event{EventSessionStart, EventUserPromptSubmit} {
		got := Runner{Policy: p, Root: root}.Run(context.Background(), Payload{
			HookEventName: ev,
			Prompt:        "CVE-2021-44228",
		})
		if got.Decision != Silent {
			t.Errorf("%s: decision = %v, want Silent", ev, got.Decision)
		}
	}
}

// One package with several advisories against it is one compromised
// dependency, not several.
func TestSessionStart_CollapsesMaliciousByPackage(t *testing.T) {
	root := memoryRepo(t, `version: "1"
last_scan:
  timestamp: "2026-09-04T00:00:00Z"
  packages: 3
  vulns: 3
findings:
  CVE-2020-0001:
    package: evil-pkg
    is_malicious: true
  CVE-2020-0002:
    package: evil-pkg
    is_malicious: true
  CVE-2020-0003:
    package: other-evil
    is_malicious: true
`)

	got := Runner{Policy: DefaultPolicy(), Root: root}.
		Run(context.Background(), Payload{HookEventName: EventSessionStart})

	if strings.Count(got.Message, "evil-pkg") != 1 {
		t.Errorf("evil-pkg should appear once, not once per advisory:\n%s", got.Message)
	}
	if !strings.Contains(got.Message, "other-evil") {
		t.Errorf("message should still list the other package:\n%s", got.Message)
	}
}
