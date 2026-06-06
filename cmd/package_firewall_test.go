package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pfw "github.com/vulnetix/cli/v3/pkg/packagefirewall"
)

func TestUpsertNetrcMachine(t *testing.T) {
	existing := "machine example.com\nlogin old\npassword old\n\nmachine packages.vulnetix.com\nlogin stale\npassword stale\n"
	got := upsertNetrcMachine(existing, "packages.vulnetix.com", "org", "key")

	if strings.Contains(got, "stale") {
		t.Fatalf("stale entry was not replaced:\n%s", got)
	}
	if !strings.Contains(got, "machine example.com") {
		t.Fatalf("unrelated entry was not preserved:\n%s", got)
	}
	if !strings.Contains(got, "machine packages.vulnetix.com\nlogin org\npassword key\n") {
		t.Fatalf("new entry missing:\n%s", got)
	}
}

func TestUpsertStructuredPackageFirewallConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	file := pfw.ConfigFile{Path: path, Content: `{"repositories":{"vulnetix":{"type":"composer"}}}` + "\n", Structured: true}

	result, err := upsertPackageFirewallConfigFile(file, false)
	if err != nil {
		t.Fatal(err)
	}
	if result != "updated package manager config" {
		t.Fatalf("result = %q", result)
	}
	gotBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(gotBytes)
	if strings.Contains(got, vulnetixBlockStart) {
		t.Fatalf("structured config contains managed comments:\n%s", got)
	}
	var parsed map[string]any
	if err := json.Unmarshal(gotBytes, &parsed); err != nil {
		t.Fatalf("structured config is not valid JSON: %v\n%s", err, got)
	}
}

func TestUpsertManagedBlock(t *testing.T) {
	existing := "before\n\n# Vulnetix Package Firewall\nold\n# End Vulnetix Package Firewall\n\nafter\n"
	block := shellEnvBlock("sh", "https://packages.vulnetix.com")
	got := upsertManagedBlock(existing, block)

	if strings.Contains(got, "\nold\n") {
		t.Fatalf("old managed block remained:\n%s", got)
	}
	if !strings.Contains(got, "export GOPROXY=\"https://packages.vulnetix.com\"") {
		t.Fatalf("new GOPROXY missing:\n%s", got)
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Fatalf("surrounding content not preserved:\n%s", got)
	}
}

func TestUpsertGoEnvValues(t *testing.T) {
	existing := "FOO=bar\nGOPROXY=https://old.example\nexport GOAUTH=off\n"
	body := "GOPROXY=https://packages.vulnetix.com\nGOAUTH=netrc\n"
	got := upsertGoEnvValues(existing, body)

	if strings.Contains(got, "old.example") || strings.Contains(got, "GOAUTH=off") {
		t.Fatalf("old Go env values remained:\n%s", got)
	}
	if !strings.Contains(got, "FOO=bar") {
		t.Fatalf("unrelated env was not preserved:\n%s", got)
	}
	if !strings.Contains(got, body) {
		t.Fatalf("new Go env body missing:\n%s", got)
	}
}

func TestUpsertPackageFirewallConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".npmrc")
	file := pfw.ConfigFile{Path: path, Content: "registry=https://packages.vulnetix.com/npm/\n"}

	result, err := upsertPackageFirewallConfigFile(file, false)
	if err != nil {
		t.Fatal(err)
	}
	if result != "updated package manager config" {
		t.Fatalf("result = %q", result)
	}
	gotBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(gotBytes)
	if !strings.Contains(got, vulnetixBlockStart) || !strings.Contains(got, "registry=https://packages.vulnetix.com/npm/") {
		t.Fatalf("managed config missing:\n%s", got)
	}

	file.Content = "registry=https://packages.vulnetix.com/npm2/\n"
	if _, err := upsertPackageFirewallConfigFile(file, false); err != nil {
		t.Fatal(err)
	}
	gotBytes, _ = os.ReadFile(path)
	got = string(gotBytes)
	if strings.Contains(got, "/npm/") || !strings.Contains(got, "/npm2/") {
		t.Fatalf("managed config was not replaced:\n%s", got)
	}
}
