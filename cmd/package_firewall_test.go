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

func TestRemoveNetrcMachine(t *testing.T) {
	existing := "machine example.com\nlogin keep\npassword keep\n\nmachine packages.vulnetix.com\nlogin org\npassword key\n"
	got := removeNetrcMachine(existing, "packages.vulnetix.com")
	if strings.Contains(got, "packages.vulnetix.com") || strings.Contains(got, "org") {
		t.Fatalf("firewall entry not removed:\n%s", got)
	}
	if !strings.Contains(got, "machine example.com\nlogin keep\npassword keep") {
		t.Fatalf("unrelated entry not preserved:\n%s", got)
	}

	// Round-trip with upsert: adding then removing yields the original neighbours.
	if only := removeNetrcMachine("machine packages.vulnetix.com\nlogin org\npassword key\n", "packages.vulnetix.com"); strings.TrimSpace(only) != "" {
		t.Fatalf("removing the sole entry should empty the file, got:\n%q", only)
	}
}

func TestRemoveManagedBlock(t *testing.T) {
	existing := "before\n\n# Vulnetix Package Firewall\nold\n# End Vulnetix Package Firewall\n\nafter\n"
	got, changed := removeManagedBlock(existing)
	if !changed {
		t.Fatal("expected block to be found")
	}
	if strings.Contains(got, "old") || strings.Contains(got, vulnetixBlockStart) {
		t.Fatalf("managed block remained:\n%s", got)
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Fatalf("surrounding content lost:\n%s", got)
	}

	onlyBlock := "# Vulnetix Package Firewall\nx\n# End Vulnetix Package Firewall\n"
	got, changed = removeManagedBlock(onlyBlock)
	if !changed || strings.TrimSpace(got) != "" {
		t.Fatalf("block-only file should become empty, got %q changed=%v", got, changed)
	}

	if _, changed := removeManagedBlock("no block here\n"); changed {
		t.Fatal("expected no change when block absent")
	}
}

func TestRemoveGoEnvValues(t *testing.T) {
	existing := "FOO=bar\nexport GOPROXY=\"https://packages.vulnetix.com\"\nexport GOAUTH=\"netrc\"\n"
	got, changed := removeGoEnvValues(existing)
	if !changed {
		t.Fatal("expected change")
	}
	if strings.Contains(got, "GOPROXY") || strings.Contains(got, "GOAUTH") {
		t.Fatalf("Go env values remained:\n%s", got)
	}
	if !strings.Contains(got, "FOO=bar") {
		t.Fatalf("unrelated env lost:\n%s", got)
	}

	got, changed = removeGoEnvValues("GOPROXY=x\nGOAUTH=netrc\n")
	if !changed || got != "" {
		t.Fatalf("file with only Go env should empty, got %q", got)
	}
}

func TestRemovePackageFirewallConfigFile_ManagedBlock(t *testing.T) {
	dir := t.TempDir()

	// File that held ONLY our block -> deleted.
	solo := filepath.Join(dir, ".npmrc")
	writeFile(t, solo, "# Vulnetix Package Firewall\nregistry=x\n# End Vulnetix Package Firewall\n")
	res, err := removePackageFirewallConfigFile(pfw.ConfigFile{Path: solo}, "packages.vulnetix.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if res != "deleted file" {
		t.Fatalf("result = %q", res)
	}
	if _, err := os.Stat(solo); !os.IsNotExist(err) {
		t.Fatal("expected file deleted")
	}

	// File with user content around our block -> block removed, file kept.
	mixed := filepath.Join(dir, ".gemrc")
	writeFile(t, mixed, "keep=1\n\n# Vulnetix Package Firewall\n:sources:\n# End Vulnetix Package Firewall\n")
	res, err = removePackageFirewallConfigFile(pfw.ConfigFile{Path: mixed}, "packages.vulnetix.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if res != "removed managed block" {
		t.Fatalf("result = %q", res)
	}
	if got := readFile(t, mixed); !strings.Contains(got, "keep=1") || strings.Contains(got, vulnetixBlockStart) {
		t.Fatalf("mixed file wrong after removal:\n%s", got)
	}

	// Not configured.
	none := filepath.Join(dir, ".other")
	writeFile(t, none, "unrelated\n")
	if res, _ := removePackageFirewallConfigFile(pfw.ConfigFile{Path: none}, "packages.vulnetix.com", false); res != "not configured" {
		t.Fatalf("result = %q", res)
	}

	// Dry-run must not modify.
	dry := filepath.Join(dir, ".dry")
	before := "# Vulnetix Package Firewall\nx\n# End Vulnetix Package Firewall\n"
	writeFile(t, dry, before)
	if res, _ := removePackageFirewallConfigFile(pfw.ConfigFile{Path: dry}, "packages.vulnetix.com", true); res != "would delete file" {
		t.Fatalf("dry result = %q", res)
	}
	if readFile(t, dry) != before {
		t.Fatal("dry-run modified the file")
	}
}

func TestRemovePackageFirewallConfigFile_Structured(t *testing.T) {
	dir := t.TempDir()

	ours := filepath.Join(dir, "settings.xml")
	writeFile(t, ours, "<settings><url>https://packages.vulnetix.com/maven/</url></settings>\n")
	res, err := removePackageFirewallConfigFile(pfw.ConfigFile{Path: ours, Structured: true}, "packages.vulnetix.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if res != "deleted file" {
		t.Fatalf("result = %q", res)
	}
	if _, err := os.Stat(ours); !os.IsNotExist(err) {
		t.Fatal("expected structured file deleted")
	}

	foreign := filepath.Join(dir, "other.xml")
	writeFile(t, foreign, "<settings><url>https://repo.maven.apache.org</url></settings>\n")
	res, _ = removePackageFirewallConfigFile(pfw.ConfigFile{Path: foreign, Structured: true}, "packages.vulnetix.com", false)
	if res != "not firewall-configured, skipped" {
		t.Fatalf("result = %q", res)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("foreign structured file should be preserved")
	}
}

func TestRemovePackageFirewallConfigFile_MergeRestoresBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paru.conf")
	writeFile(t, path, "[options]\nAurUrl = https://packages.vulnetix.com/aur\nColor\n")
	writeFile(t, path+".vulnetix.bak", "[options]\nColor\n")

	res, err := removePackageFirewallConfigFile(pfw.ConfigFile{Path: path, Merge: func(s string) (string, error) { return s, nil }}, "packages.vulnetix.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if res != "restored from backup" {
		t.Fatalf("result = %q", res)
	}
	if got := readFile(t, path); strings.Contains(got, "vulnetix.com") || !strings.Contains(got, "Color") {
		t.Fatalf("backup not restored:\n%s", got)
	}
	if _, err := os.Stat(path + ".vulnetix.bak"); !os.IsNotExist(err) {
		t.Fatal("backup should be removed after restore")
	}
}

func TestStripMergeKeys(t *testing.T) {
	// paru.conf INI
	paru, changed := stripMergeKeys("/x/paru.conf", "[options]\nColor\nAurUrl = https://packages.vulnetix.com/aur\nAurRpcUrl = https://packages.vulnetix.com/aur/rpc\n")
	if !changed || strings.Contains(paru, "AurUrl") || !strings.Contains(paru, "Color") {
		t.Fatalf("paru strip wrong (changed=%v):\n%s", changed, paru)
	}

	// yay config.json
	yay, changed := stripMergeKeys("/x/config.json", `{"aururl":"https://packages.vulnetix.com/aur","aurrpcurl":"x","editor":"vim"}`)
	if !changed || strings.Contains(yay, "aururl") || !strings.Contains(yay, "editor") {
		t.Fatalf("yay strip wrong (changed=%v):\n%s", changed, yay)
	}
}

func TestRemoveNetrcCredential(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".netrc")
	writeFile(t, path, "machine example.com\nlogin a\npassword b\n\nmachine packages.vulnetix.com\nlogin org\npassword key\n")

	if res, _ := removeNetrcCredential(path, "packages.vulnetix.com", true); res != "would remove netrc credential" {
		t.Fatalf("dry result = %q", res)
	}
	if !strings.Contains(readFile(t, path), "packages.vulnetix.com") {
		t.Fatal("dry-run modified netrc")
	}

	res, err := removeNetrcCredential(path, "packages.vulnetix.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if res != "removed netrc credential" {
		t.Fatalf("result = %q", res)
	}
	got := readFile(t, path)
	if strings.Contains(got, "packages.vulnetix.com") || !strings.Contains(got, "example.com") {
		t.Fatalf("netrc wrong after removal:\n%s", got)
	}

	// Sole entry -> file deleted.
	solo := filepath.Join(dir, "solo")
	writeFile(t, solo, "machine packages.vulnetix.com\nlogin org\npassword key\n")
	res, _ = removeNetrcCredential(solo, "packages.vulnetix.com", false)
	if res != "removed netrc credential (file deleted)" {
		t.Fatalf("result = %q", res)
	}
	if _, err := os.Stat(solo); !os.IsNotExist(err) {
		t.Fatal("expected netrc deleted")
	}

	// Absent.
	if res, _ := removeNetrcCredential(filepath.Join(dir, "nope"), "packages.vulnetix.com", false); res != "not configured" {
		t.Fatalf("result = %q", res)
	}
}

func TestResolveUninstallTargets(t *testing.T) {
	if _, err := resolveUninstallTargets(nil, nil, false); err == nil {
		t.Fatal("expected error with no selector")
	}
	if _, err := resolveUninstallTargets([]string{"npm"}, nil, true); err == nil {
		t.Fatal("expected error with multiple selectors")
	}

	all, err := resolveUninstallTargets(nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(pfw.All()) {
		t.Fatalf("--all returned %d, want %d", len(all), len(pfw.All()))
	}

	args, err := resolveUninstallTargets([]string{"npm", "pypi"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 2 || args[0].Command != "npm" || args[1].Command != "pypi" {
		t.Fatalf("targeted returned %+v", args)
	}

	except, err := resolveUninstallTargets(nil, []string{"aur"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(except) != len(pfw.All())-1 {
		t.Fatalf("--except returned %d, want %d", len(except), len(pfw.All())-1)
	}
	for _, e := range except {
		if e.ID == "aur" {
			t.Fatal("aur should be excluded")
		}
	}

	if _, err := resolveUninstallTargets([]string{"bogus"}, nil, false); err == nil {
		t.Fatal("expected error for unknown ecosystem")
	}

	if eco, ok := resolveEcosystem("go-dev"); !ok || eco.ID != "go-dev" {
		t.Fatal("go-dev should resolve")
	}
}

// TestUninstallRoundTripNpm proves configure and uninstall line up: writing the
// real npm config files then removing them leaves nothing behind.
func TestUninstallRoundTripNpm(t *testing.T) {
	home := t.TempDir()
	eco, _ := pfw.ByCommand("npm")
	files, err := pfw.ConfigFiles(eco, pfw.ConfigOptions{HomeDir: home, ProxyURL: "https://packages.vulnetix.com", OrgID: "org", APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if _, err := upsertPackageFirewallConfigFile(f, false); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range files {
		res, err := removePackageFirewallConfigFile(f, "packages.vulnetix.com", false)
		if err != nil {
			t.Fatal(err)
		}
		if res != "deleted file" {
			t.Fatalf("%s: result = %q", f.Path, res)
		}
		if _, err := os.Stat(f.Path); !os.IsNotExist(err) {
			t.Fatalf("%s not removed", f.Path)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
