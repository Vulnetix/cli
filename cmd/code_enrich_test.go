package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/report"
)

func TestResourceAt(t *testing.T) {
	tf := []string{
		`provider "aws" {`, `  region = "us-east-1"`, `}`, ``,
		`resource "aws_s3_bucket" "logs" {`, `  bucket = "x"`, `  acl    = "public-read"`, `}`, ``,
		`data "aws_iam_policy_document" "p" {`, `  statement {}`, `}`, ``,
		`module "net" {`, `  source = "./net"`, `}`, ``,
		`variable "v" {`, `  default = "x"`, `}`,
	}
	for _, c := range []struct {
		line int
		want string
		at   int
	}{
		{7, "aws_s3_bucket.logs", 5}, {5, "aws_s3_bucket.logs", 5}, {11, "data.aws_iam_policy_document.p", 10},
		{15, "module.net", 14}, {2, "", 0}, {18, "", 0},
	} {
		got, at := resourceAt("main.tf", tf, c.line)
		if got != c.want || at != c.at {
			t.Errorf("tf line %d: got %q@%d want %q@%d", c.line, got, at, c.want, c.at)
		}
	}

	k8s := []string{
		`apiVersion: v1`, `kind: ConfigMap`, `metadata:`, `  name: cfg`, `---`,
		`apiVersion: apps/v1`, `kind: Deployment`, `metadata:`, `  name: api`, `  labels:`, `    a: b`,
		`spec:`, `  template:`, `    spec:`, `      containers:`, `        - securityContext:`, `            privileged: true`,
	}
	if got, at := resourceAt("k8s/api.yaml", k8s, 17); got != "Deployment/api" || at != 7 {
		t.Errorf("k8s: got %q@%d", got, at)
	}
	if got, _ := resourceAt("k8s/api.yaml", k8s, 4); got != "ConfigMap/cfg" {
		t.Errorf("k8s first document: got %q", got)
	}

	compose := []string{`services:`, `  web:`, `    image: nginx`, `  api:`, `    image: api`, `    privileged: true`, `volumes:`, `  data: {}`}
	if got, at := resourceAt("docker-compose.yml", compose, 6); got != "service api" || at != 4 {
		t.Errorf("compose: got %q@%d", got, at)
	}

	docker := []string{`FROM golang:1.22 AS build`, `RUN go build`, `FROM alpine:latest`, `COPY --from=build /a /a`}
	if got, at := resourceAt("Dockerfile", docker, 4); got != "FROM alpine:latest" || at != 3 {
		t.Errorf("dockerfile: got %q@%d", got, at)
	}
	if got, _ := resourceAt("main.go", []string{"package main"}, 1); got != "" {
		t.Errorf("a Go file has no resource, got %q", got)
	}
}

func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// A secret's history is read from git: committed lines name their commit, and
// lines in files git has never seen are "not committed". Outside a repository
// nothing is asked, so "unknown" can never read as "not committed".
func TestBlameSecrets(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "prod.env"), []byte("A=1\nKEY=value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "add", "prod.env")
	gitIn(t, dir, "commit", "-q", "-m", "add env")
	if err := os.WriteFile(filepath.Join(dir, "new.env"), []byte("KEY=value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A committed file with one new, uncommitted line.
	if err := os.WriteFile(filepath.Join(dir, "prod.env"), []byte("A=1\nKEY=value\nOTHER=value\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cr := &report.CodeReport{Label: "Secrets", Findings: []report.CodeFinding{
		{RuleID: "r", Path: "prod.env", Line: 2},
		{RuleID: "r", Path: "new.env", Line: 1},
		{RuleID: "r", Path: "prod.env", Line: 3},
	}}
	blameSecrets(cr, dir)
	f := cr.Findings
	if !f[0].Blamed || !f[0].Committed || len(f[0].Commit) != 12 || f[0].CommittedAt.IsZero() {
		t.Errorf("committed line: %+v", f[0])
	}
	if !f[1].Blamed || f[1].Committed {
		t.Errorf("untracked file must be not committed: %+v", f[1])
	}
	if !f[2].Blamed || f[2].Committed {
		t.Errorf("an edited line is not committed yet: %+v", f[2])
	}

	outside := t.TempDir()
	cr2 := &report.CodeReport{Label: "Secrets", Findings: []report.CodeFinding{{RuleID: "r", Path: "x.env", Line: 1}}}
	blameSecrets(cr2, outside)
	if cr2.Findings[0].Blamed {
		t.Error("outside a repository nothing is known, so Blamed must stay false")
	}
}

func TestFindResourcesReadsEachFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("resource \"aws_db_instance\" \"main\" {\n  publicly_accessible = true\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cr := &report.CodeReport{Label: "IaC", Findings: []report.CodeFinding{
		{Path: "main.tf", Line: 2}, {Path: "missing.tf", Line: 1},
	}}
	enrichCodeReport(cr, dir)
	if cr.Findings[0].Resource != "aws_db_instance.main" || cr.Findings[0].ResourceLine != 1 {
		t.Errorf("got %+v", cr.Findings[0])
	}
	if cr.Findings[1].Resource != "" {
		t.Errorf("an unreadable file has no resource, got %q", cr.Findings[1].Resource)
	}
	// SAST findings are not enriched: it costs a read per file and means nothing.
	sastReport := &report.CodeReport{Label: "SAST", Findings: []report.CodeFinding{{Path: "main.tf", Line: 2}}}
	enrichCodeReport(sastReport, dir)
	if sastReport.Findings[0].Resource != "" {
		t.Error("SAST findings must not be enriched")
	}
}

// A copy found in a past commit becomes a place at its real path, committed by
// definition, and its commit's date is read from git.
func TestBlameSecretsReadsHistoryCopies(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "old.env"), []byte("KEY=value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "add", "old.env")
	gitIn(t, dir, "commit", "-q", "-m", "add")
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	short := strings.TrimSpace(string(out))

	cr := &report.CodeReport{Label: "Secrets", Findings: []report.CodeFinding{
		{RuleID: "r", Path: "__git_history__/" + short + "/old.env", Line: 1},
	}}
	blameSecrets(cr, dir)
	f := cr.Findings[0]
	if f.Path != "old.env" || !f.InHistory || !f.Committed || f.Commit != short || f.CommittedAt.IsZero() {
		t.Errorf("history copy: %+v", f)
	}
}
