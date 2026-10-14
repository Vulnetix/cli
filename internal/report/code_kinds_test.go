package report

import (
	"strings"
	"testing"
	"time"
)

var kindsNow = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

// A fake, well-formed key: never a live provider format.
const fakeKey = "AKIAZZZZ9X8Y7W6V5U4T"

func secretsFixture() CodeReport {
	at := time.Date(2026, 9, 3, 9, 0, 0, 0, time.UTC)
	key := func(path string, line int, committed bool) CodeFinding {
		f := CodeFinding{RuleID: "VNX-SEC-001", Name: "AWS access key ID", Severity: "critical", Kind: "secrets",
			Path: path, Line: line, Message: "AWS access key ID found", Snippet: "aws_access_key_id = \"" + fakeKey + "\"",
			Description: "An AWS access key ID (AKIA prefix) was found in source code.", HelpURI: "https://example.invalid/vnx-sec-001", CWE: []int{798}, Blamed: true}
		if committed {
			f.Committed, f.Commit, f.CommittedAt = true, "a1b2c3d4e5f6", at
		}
		return f
	}
	return CodeReport{Label: "Secrets", RulesLoaded: 1090, Findings: []CodeFinding{
		key("deploy/prod.tfvars", 14, true),
		key(".env.example", 3, true),
		key("scripts/bootstrap.sh", 9, false),
		{RuleID: "VNX-SEC-004", Name: "GitHub or GitLab token", Severity: "critical", Kind: "secrets", Path: "scripts/release.sh", Line: 22,
			Snippet: "TOKEN=ghp_9aZ3kQ7mP2xV8nL5cR1tY6wB4dF0hJ", Blamed: true, Committed: true, Commit: "9f8e7d6c5b4a", CommittedAt: kindsNow.Add(-72 * time.Hour)},
		{RuleID: "VNX-SEC-042", Name: "Slack webhook URL", Severity: "high", Kind: "secrets", Path: "internal/notify/slack.go", Line: 31,
			Snippet: "const hook = \"https://hooks.example.invalid/T00/B00/Zq9Xw7Lk2Pm5Vn8Rc3Td6Yb1\"", Blamed: true},
		{RuleID: "VNX-SEC-006", Name: "Stripe secret key", Severity: "high", Kind: "secrets", Path: "internal/billing/stripe_test.go", Line: 18,
			Snippet: "key := \"sk_" + "test_Ab3De6Gh9Jk2Mn5Pq8St1Vw4\"", TestSuite: true},
		{RuleID: "VNX-SEC-072", Name: "Generic high-entropy API key", Severity: "medium", Kind: "secrets", Path: "cmd/config.go", Line: 40,
			Snippet: "apiKey := \"Zx9Cv8Bn7Mq6We5Rt4Yu3Io2Pa1Sd\""},
	}}
}

func iacFixture() CodeReport {
	f := func(id, title, sev, path string, line int, res string, resLine int, cwe int, snip string) CodeFinding {
		return CodeFinding{RuleID: id, Name: title, Severity: sev, Kind: "iac", Path: path, Line: line, Resource: res, ResourceLine: resLine, CWE: []int{cwe}, Snippet: snip, Message: title}
	}
	return CodeReport{Label: "IaC", RulesLoaded: 774, RulesTotal: 2865, Findings: []CodeFinding{
		f("VNX-TF-001", "Bucket is publicly readable", "high", "infra/storage.tf", 15, "aws_s3_bucket.logs", 12, 732, `acl = "public-read"`),
		f("KICS-S3-ACL", "S3 bucket ACL allows public read", "high", "infra/storage.tf", 15, "aws_s3_bucket.logs", 12, 732, `acl = "public-read"`),
		f("REGULA-S3-1", "ACL public-read", "high", "infra/storage.tf", 15, "aws_s3_bucket.logs", 12, 732, `acl = "public-read"`),
		f("TRIVY-S3-ENC", "No server-side encryption", "high", "infra/storage.tf", 12, "aws_s3_bucket.logs", 12, 311, `resource "aws_s3_bucket" "logs" {`),
		f("VNX-TF-003", "Database is publicly accessible", "high", "infra/db.tf", 9, "aws_db_instance.main", 3, 284, `publicly_accessible = true`),
		f("VNX-DOCKER-005", "Container runs privileged", "critical", "k8s/api.yaml", 24, "Deployment/api", 1, 250, `privileged: true`),
		f("REGULA-TAGS", "Resource has no owner or env tag", "medium", "infra/storage.tf", 12, "aws_s3_bucket.logs", 12, 1, ""),
		f("REGULA-TAGS", "Resource has no owner or env tag", "medium", "infra/db.tf", 3, "aws_db_instance.main", 3, 1, ""),
		f("TRIVY-VER", "Bucket versioning disabled", "low", "infra/storage.tf", 12, "aws_s3_bucket.logs", 12, 2, ""),
		{RuleID: "VNX-TF-001", Name: "Bucket is publicly readable", Severity: "high", Kind: "iac", Path: "infra/testdata/x.tf", Line: 3, TestSuite: true},
	}}
}

func containersFixture() CodeReport {
	f := func(id, title, sev, path string, line int, res string, cwe int, snip string) CodeFinding {
		return CodeFinding{RuleID: id, Name: title, Severity: sev, Kind: "oci", Path: path, Line: line, Resource: res, CWE: []int{cwe}, Snippet: snip, Message: title}
	}
	return CodeReport{Label: "Container", RulesLoaded: 180, Findings: []CodeFinding{
		f("VNX-DOCKER-005", "Privileged container", "critical", "docker-compose.yml", 18, "service api", 250, "privileged: true"),
		f("VNX-DOCKER-001", "Final stage runs as root", "medium", "Dockerfile", 1, "FROM alpine:latest", 250, ""),
		f("EMBARK-DOCKER-01", "Dockerfile does not set USER", "medium", "Dockerfile", 1, "FROM alpine:latest", 250, ""),
		f("VNX-DOCKER-002", "Base image not pinned", "medium", "Dockerfile", 25, "FROM alpine:latest", 829, "FROM alpine:latest"),
		f("VNX-DOCKER-008", "OS packages not pinned", "low", "Dockerfile", 7, "FROM alpine:latest", 1357, "apk add curl git"),
		{RuleID: "VNX-DOCKER-001", Name: "Final stage runs as root", Severity: "high", Kind: "oci", Path: "internal/sast/containerfile_test.go", Line: 1, TestSuite: true},
	}}
}

func TestGoldenSecrets(t *testing.T) {
	r := secretsFixture()
	o := Options{Command: "secrets", Now: kindsNow}
	golden(t, "secrets_110", RenderCode(r, o, plainTerm(110, true)))
	golden(t, "secrets_50", RenderCode(r, o, plainTerm(50, true)))
	out, ok := RenderCodeExplain(r, "VNX-SEC-001", o, plainTerm(100, true))
	if !ok {
		t.Fatal("explain found nothing")
	}
	golden(t, "secrets_explain", out)
}

func TestGoldenIaC(t *testing.T) {
	r := iacFixture()
	o := Options{Command: "iac", Now: kindsNow}
	golden(t, "iac_110", RenderCode(r, o, plainTerm(110, true)))
	golden(t, "iac_50", RenderCode(r, o, plainTerm(50, true)))
}

func TestGoldenContainers(t *testing.T) {
	r := containersFixture()
	o := Options{Command: "containers", Now: kindsNow}
	golden(t, "containers_110", RenderCode(r, o, plainTerm(110, true)))
	golden(t, "containers_50", RenderCode(r, o, plainTerm(50, true)))
}

// The same value written in three places is one credential, because rotating
// it once fixes all three; that is the unit the report counts.
func TestSecretsAreGroupedByCredential(t *testing.T) {
	out := RenderCode(secretsFixture(), Options{Command: "secrets", Now: kindsNow}, plainTerm(110, true))
	for _, want := range []string{
		"5 credentials in 7 places",
		"2 to rotate", "1 not committed", "1 in tests",
		"committed in a1b2c3d, 41 days ago",
		"committed in 9f8e7d6, 3 days ago",
		"also in deploy/prod.tfvars:14",
		"ROTATE NOW", "NOT COMMITTED", "IN TESTS",
		"vulnetix secrets --explain VNX-SEC-001",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// The three AWS places are one row.
	if n := strings.Count(out, "VNX-SEC-001"); n != 2 { // the row and the NEXT command
		t.Errorf("VNX-SEC-001 appears %d times, want 2 (one credential, one NEXT line):\n%s", n, out)
	}
}

// A line with no token to identify a value is never merged with another line.
func TestCredentialKey(t *testing.T) {
	a := CodeFinding{Path: "a", Line: 1, Snippet: `aws_access_key_id = "` + fakeKey + `"`}
	b := CodeFinding{Path: "b", Line: 9, Snippet: `export AWS_ACCESS_KEY_ID=` + fakeKey}
	if credentialKey(a) != credentialKey(b) {
		t.Error("one key written two ways should be one credential")
	}
	other := CodeFinding{Path: "c", Line: 2, Snippet: `aws_access_key_id = "AKIAQQQQ1W2E3R4T5Y6U"`}
	if credentialKey(a) == credentialKey(other) {
		t.Error("two different keys must not merge")
	}
	p1 := CodeFinding{Path: "x", Line: 1, Snippet: "-----BEGIN PRIVATE KEY-----"}
	p2 := CodeFinding{Path: "y", Line: 1, Snippet: "-----BEGIN PRIVATE KEY-----"}
	if credentialKey(p1) == credentialKey(p2) {
		t.Error("lines with no identifiable value must stay separate")
	}
	if k := credentialKey(a); strings.Contains(k, fakeKey) || len(k) != 16 {
		t.Errorf("the key must be a hash, got %q", k)
	}
}

// Git being unreadable is not good news: with no blame the credential is still
// something to rotate, not something "not committed".
func TestUnblamedSecretIsStillRotated(t *testing.T) {
	r := CodeReport{Label: "Secrets", Findings: []CodeFinding{
		{RuleID: "VNX-SEC-001", Severity: "critical", Kind: "secrets", Path: "a.env", Line: 1, Snippet: "K=" + fakeKey},
	}}
	out := RenderCode(r, Options{Command: "secrets", Now: kindsNow}, plainTerm(110, true))
	if !strings.Contains(out, "ROTATE NOW") || strings.Contains(out, "NOT COMMITTED") {
		t.Errorf("an unknown history must land in ROTATE NOW:\n%s", out)
	}
}

func TestSecretsNeverPrintTheValueOrItsLine(t *testing.T) {
	r := secretsFixture()
	for name, out := range map[string]string{
		"default": RenderCode(r, Options{Now: kindsNow}, plainTerm(110, true)),
		"-v":      RenderCode(r, Options{Verbosity: 1, Now: kindsNow}, plainTerm(110, true)),
		"-vv":     RenderCode(r, Options{Verbosity: 2, Now: kindsNow}, plainTerm(80, true)),
		"tests":   RenderCode(r, Options{Show: Set([]string{"tests"}), Now: kindsNow}, plainTerm(110, true)),
		"plain":   RenderCodePlain(r, Options{}, plainTerm(110, false)),
		"github":  RenderCodeGitHub(r),
	} {
		for _, secret := range []string{fakeKey, "ghp_9aZ3", "sk_test_Ab3", "Zq9Xw7Lk2", "Zx9Cv8Bn7"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s output printed %q:\n%s", name, secret, out)
			}
		}
	}
	for _, q := range []string{"VNX-SEC-001", "VNX-SEC-004", "VNX-SEC-042", "scripts/bootstrap.sh"} {
		for _, o := range []Options{{Now: kindsNow}, {Now: kindsNow, Verbosity: 2}} {
			out, ok := RenderCodeExplain(r, q, o, plainTerm(100, true))
			if !ok {
				t.Fatalf("explain %s found nothing", q)
			}
			for _, secret := range []string{fakeKey, "ghp_9aZ3", "Zq9Xw7Lk2", "aws_access_key_id ="} {
				if strings.Contains(out, secret) {
					t.Errorf("--explain %s printed %q:\n%s", q, secret, out)
				}
			}
		}
	}
}

func TestSecretsExplainGivesTheRotationOrder(t *testing.T) {
	out, _ := RenderCodeExplain(secretsFixture(), "VNX-SEC-001", Options{Now: kindsNow}, plainTerm(100, true))
	for _, want := range []string{
		"WHAT TO DO, IN THIS ORDER", "1  Revoke the credential", "2  Check the provider's access logs from 2026-09-03",
		"3  Issue a replacement", "4  Remove it from the 3 places below",
		"committed a1b2c3d", "not committed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// A credential that was never committed has a shorter, different list.
	fresh, _ := RenderCodeExplain(secretsFixture(), "VNX-SEC-042", Options{Now: kindsNow}, plainTerm(100, true))
	if strings.Contains(fresh, "access logs") || !strings.Contains(fresh, "If it was ever committed") {
		t.Errorf("an uncommitted secret should not claim an exposure window:\n%s", fresh)
	}
}

// Seven packs flag the same line. They are one problem, and -v unfolds them.
func TestIaCFoldsTheSameProblem(t *testing.T) {
	r := iacFixture()
	out := RenderCode(r, Options{Command: "iac", Now: kindsNow}, plainTerm(110, true))
	for _, want := range []string{"aws_s3_bucket.logs", "infra/storage.tf:12", "VNX-TF-001 · KICS-S3-ACL · REGULA-S3-1", "folded as the same problem", "NEEDS ACTION", "CAN WAIT", "2 resources"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "Bucket is publicly readable"); n != 1 {
		t.Errorf("the public ACL should be one row, got %d:\n%s", n, out)
	}
	verbose := RenderCode(r, Options{Command: "iac", Verbosity: 1, Now: kindsNow}, plainTerm(110, true))
	if strings.Contains(verbose, "folded") || !strings.Contains(verbose, "S3 bucket ACL allows public read") {
		t.Errorf("-v must show every finding, unfolded:\n%s", verbose)
	}
	// A different weakness on the same line stays its own problem.
	if !strings.Contains(out, "No server-side encryption") {
		t.Errorf("distinct weaknesses must not fold:\n%s", out)
	}
}

func TestContainersCardsCarryFixes(t *testing.T) {
	out := RenderCode(containersFixture(), Options{Command: "containers", Now: kindsNow}, plainTerm(110, true))
	for _, want := range []string{
		"2 images", "1 needs action", "can wait", "IN TESTS",
		"fix: remove privileged", "fix: add USER 65532:65532",
		"vulnetix containers --explain Dockerfile",
		"VNX-DOCKER-001 · EMBARK-DOCKER-01",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// A pack's rule with no recorded fix prints no fix line, not a vague one.
	if strings.Contains(out, "EMBARK-DOCKER-01 fix") {
		t.Errorf("unexpected fix text:\n%s", out)
	}
}

// Every NEXT command must exist and every fixed rule must be a built-in one.
func TestKindsNextCommandsAreRealFlags(t *testing.T) {
	for name, r := range map[string]CodeReport{"secrets": secretsFixture(), "iac": iacFixture(), "containers": containersFixture()} {
		out := RenderCode(r, Options{Command: name, Now: kindsNow}, plainTerm(110, true))
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "vulnetix" {
				continue
			}
			if fields[1] != name {
				t.Errorf("%s NEXT names another command: %q", name, line)
			}
			for _, f := range fields[2:] {
				if strings.HasPrefix(f, "-") && f != "--explain" && f != "-v" && f != "--show" && f != "--exclude" {
					t.Errorf("%s NEXT uses an unknown flag %q", name, f)
				}
				if f == "-o" {
					t.Errorf("%s NEXT suggests -o, which code --explain does not have", name)
				}
			}
		}
	}
	for id := range containerFixes {
		if !strings.HasPrefix(id, "VNX-DOCKER-") {
			t.Errorf("containerFixes has a non-built-in rule %q", id)
		}
	}
}

func TestKindsCleanAndQuiet(t *testing.T) {
	for _, label := range []string{"Secrets", "IaC", "Container"} {
		r := CodeReport{Label: label, RulesLoaded: 5}
		if got := RenderCode(r, Options{Quiet: true}, plainTerm(100, true)); got != "" {
			t.Errorf("%s: quiet and clean must print nothing, got %q", label, got)
		}
		if got := RenderCode(r, Options{}, plainTerm(100, true)); !strings.Contains(got, "No ") {
			t.Errorf("%s: a clean run should say so:\n%s", label, got)
		}
	}
}

func TestAgoPhrase(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want string
	}{
		{2 * time.Hour, "today"}, {24 * time.Hour, "1 day ago"}, {41 * 24 * time.Hour, "41 days ago"},
		{200 * 24 * time.Hour, "6 months ago"}, {3 * 365 * 24 * time.Hour, "3 years ago"},
	} {
		if got := agoPhrase(kindsNow, kindsNow.Add(-c.d)); got != c.want {
			t.Errorf("%v: got %q want %q", c.d, got, c.want)
		}
	}
}

// A copy in a past commit is the same place as the working line, and a secret
// deleted from the tree but still in history is something to rotate.
func TestSecretsInHistory(t *testing.T) {
	live := CodeFinding{RuleID: "VNX-SEC-001", Name: "AWS access key ID", Severity: "critical", Kind: "secrets", Path: "prod.tfvars", Line: 1,
		Snippet: "k = \"" + fakeKey + "\"", Blamed: true, Committed: true, Commit: "c5c1dab", CommittedAt: kindsNow.Add(-48 * time.Hour)}
	hist := live
	hist.InHistory = true
	r := CodeReport{Label: "Secrets", Findings: []CodeFinding{live, hist}}
	out := RenderCode(r, Options{Command: "secrets", Now: kindsNow}, plainTerm(110, true))
	if !strings.Contains(out, "1 credential in 1 place") || strings.Contains(out, "also in") {
		t.Errorf("the working line and its history copy are one place:\n%s", out)
	}

	gone := CodeReport{Label: "Secrets", Findings: []CodeFinding{hist}}
	out = RenderCode(gone, Options{Command: "secrets", Now: kindsNow}, plainTerm(110, true))
	for _, want := range []string{"ROTATE NOW", "removed from the tree, still in history: committed in c5c1dab, 2 days ago", "(history c5c1dab)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
