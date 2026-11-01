package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfigFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func runConfigValidate(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := newConfigValidateCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

const validGate = "apiVersion: vulnetix.com/v1\nkind: QualityGate\nmetadata: {name: default}\nspec: {severity: high, blockMalware: true}\n"

func TestConfigValidateWalksDirectoriesAndSplitsDocuments(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, dir, "a/gate.yaml", "# comment only\n---\n"+validGate)
	writeConfigFile(t, dir, "notes.txt", "not a document")
	out, err := runConfigValidate(t, "", "-f", dir)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "1 documents valid in 1 files") {
		t.Fatalf("got %q", out)
	}
}

func TestConfigValidateReportsEveryProblemWithItsLocation(t *testing.T) {
	dir := t.TempDir()
	p := writeConfigFile(t, dir, "gate.yaml", validGate+"---\napiVersion: vulnetix.com/v1\nkind: QualityGate\nmetadata: {name: default}\nspec: {severity: urgent}\n")
	out, err := runConfigValidate(t, "", "-f", p)
	if err == nil {
		t.Fatal("want an error")
	}
	if ExitCode(err) != ExitFailure {
		t.Fatalf("exit %d", ExitCode(err))
	}
	if !strings.Contains(out, p+" (document 2)") || !strings.Contains(out, "/spec/severity") {
		t.Fatalf("got %q", out)
	}
}

func TestConfigValidateRejectsDuplicateKindAndName(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, dir, "one.yaml", validGate)
	writeConfigFile(t, dir, "two.yaml", validGate)
	out, err := runConfigValidate(t, "", "-f", dir)
	if err == nil || !strings.Contains(out, `QualityGate "default" is already defined in`) {
		t.Fatalf("err=%v out=%q", err, out)
	}
}

func TestConfigValidateReadsStdin(t *testing.T) {
	out, err := runConfigValidate(t, validGate, "-f", "-")
	if err != nil || !strings.Contains(out, "1 documents valid") {
		t.Fatalf("err=%v out=%q", err, out)
	}
}

func TestConfigValidateWithNoConfigDirectoryIsNotAnError(t *testing.T) {
	t.Chdir(t.TempDir())
	out, err := runConfigValidate(t, "")
	if err != nil || !strings.Contains(out, "no config documents") {
		t.Fatalf("err=%v out=%q", err, out)
	}
}

func TestConfigSchemaPrintsKnownKindsOnly(t *testing.T) {
	cmd := newConfigSchemaCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"QualityGate"})
	if err := cmd.Execute(); err != nil || !strings.Contains(out.String(), `"title": "QualityGate"`) {
		t.Fatalf("err=%v", err)
	}
	cmd = newConfigSchemaCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"Nope"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("unknown kind accepted")
	}
}
