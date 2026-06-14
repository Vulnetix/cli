package packagefirewall

import (
	"strings"
	"testing"
)

func opts() ConfigOptions {
	return ConfigOptions{
		HomeDir:  "/home/test",
		ProxyURL: "https://packages.vulnetix.com",
		OrgID:    "org-123",
		APIKey:   "secret",
	}
}

// TestNPMConfig covers the npm-ecosystem clients. .npmrc serves npm, pnpm, bun,
// and Yarn Classic (v1); Yarn Berry (v2+) ignores .npmrc and gets its own
// .yarnrc.yml. base64("org-123:secret") == "b3JnLTEyMzpzZWNyZXQ=".
func TestNPMConfig(t *testing.T) {
	eco, _ := ByCommand("npm")
	files, err := ConfigFiles(eco, opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("npm files = %d, want 2 (.npmrc + .yarnrc.yml)", len(files))
	}
	if files[0].Path != "/home/test/.npmrc" {
		t.Fatalf("path = %q", files[0].Path)
	}
	for _, want := range []string{
		"registry=https://packages.vulnetix.com/npm/",
		"//packages.vulnetix.com/npm/:_auth=b3JnLTEyMzpzZWNyZXQ=",
	} {
		if !strings.Contains(files[0].Content, want) {
			t.Errorf("npm config missing %q:\n%s", want, files[0].Content)
		}
	}

	if files[1].Path != "/home/test/.yarnrc.yml" {
		t.Fatalf("yarn berry path = %q", files[1].Path)
	}
	for _, want := range []string{
		`npmRegistryServer: "https://packages.vulnetix.com/npm/"`,
		`  "//packages.vulnetix.com/npm/":`,
		"    npmAlwaysAuth: true",
		`    npmAuthIdent: "org-123:secret"`,
	} {
		if !strings.Contains(files[1].Content, want) {
			t.Errorf("yarn berry config missing %q:\n%s", want, files[1].Content)
		}
	}
}

// TestPyPIConfig covers the pypi-ecosystem clients. pip.conf serves pip and
// pipenv; uv ignores pip.conf and gets its own uv.toml.
func TestPyPIConfig(t *testing.T) {
	eco, _ := ByCommand("pypi")
	files, err := ConfigFiles(eco, opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("pypi files = %d, want 2 (pip.conf + uv.toml)", len(files))
	}
	if files[0].Path != "/home/test/.config/pip/pip.conf" {
		t.Fatalf("pip path = %q", files[0].Path)
	}
	want := "index-url = https://org-123:secret@packages.vulnetix.com/pypi/simple/"
	if !strings.Contains(files[0].Content, want) {
		t.Errorf("pypi config missing %q:\n%s", want, files[0].Content)
	}

	if files[1].Path != "/home/test/.config/uv/uv.toml" {
		t.Fatalf("uv path = %q", files[1].Path)
	}
	for _, want := range []string{
		"[[index]]",
		`url = "https://org-123:secret@packages.vulnetix.com/pypi/simple/"`,
		"default = true",
	} {
		if !strings.Contains(files[1].Content, want) {
			t.Errorf("uv config missing %q:\n%s", want, files[1].Content)
		}
	}
}

func TestMavenConfig(t *testing.T) {
	eco, _ := ByCommand("maven")
	files, err := ConfigFiles(eco, opts())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<id>vulnetix-package-firewall</id>",
		"<username>org-123</username>",
		"<password>secret</password>",
		"<url>https://packages.vulnetix.com/maven/</url>",
	} {
		if !strings.Contains(files[0].Content, want) {
			t.Errorf("maven config missing %q:\n%s", want, files[0].Content)
		}
	}
}

func TestHexConfig(t *testing.T) {
	eco, _ := ByCommand("hex")
	files, err := ConfigFiles(eco, opts())
	if err != nil {
		t.Fatal(err)
	}
	if files[0].Path != "/home/test/.config/vulnetix/package-firewall/hex.env" {
		t.Fatalf("path = %q", files[0].Path)
	}
	if want := `export HEX_MIRROR="https://org-123:secret@packages.vulnetix.com/hex"`; !strings.Contains(files[0].Content, want) {
		t.Errorf("hex config missing %q:\n%s", want, files[0].Content)
	}
}

func TestConanConfig(t *testing.T) {
	eco, _ := ByCommand("conan")
	files, err := ConfigFiles(eco, opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("files = %d, want 2", len(files))
	}
	if files[0].Path != "/home/test/.conan2/remotes.json" || !files[0].Structured {
		t.Fatalf("unexpected remotes file: %+v", files[0])
	}
	for _, want := range []string{
		`"name": "vulnetix"`,
		`"url": "https://packages.vulnetix.com/conan"`,
		`"name": "conancenter"`,
		`"disabled": true`,
	} {
		if !strings.Contains(files[0].Content, want) {
			t.Errorf("conan remotes missing %q:\n%s", want, files[0].Content)
		}
	}
	if files[1].Path != "/home/test/.conan2/credentials.json" || !files[1].Structured {
		t.Fatalf("unexpected credentials file: %+v", files[1])
	}
	for _, want := range []string{
		`"remote": "vulnetix"`,
		`"user": "org-123"`,
		`"password": "secret"`,
	} {
		if !strings.Contains(files[1].Content, want) {
			t.Errorf("conan credentials missing %q:\n%s", want, files[1].Content)
		}
	}
}

func TestCRANConfig(t *testing.T) {
	eco, _ := ByCommand("cran")
	files, err := ConfigFiles(eco, opts())
	if err != nil {
		t.Fatal(err)
	}
	if files[0].Path != "/home/test/.Rprofile" {
		t.Fatalf("path = %q", files[0].Path)
	}
	for _, want := range []string{
		`options(repos = c(CRAN = "https://org-123:secret@packages.vulnetix.com/cran"))`,
		`options(download.file.method = "libcurl")`,
	} {
		if !strings.Contains(files[0].Content, want) {
			t.Errorf("cran config missing %q:\n%s", want, files[0].Content)
		}
	}
}

func TestHelmConfig(t *testing.T) {
	eco, _ := ByCommand("helm")
	files, err := ConfigFiles(eco, opts())
	if err != nil {
		t.Fatal(err)
	}
	if files[0].Path != "/home/test/.config/helm/repositories.yaml" || !files[0].Structured {
		t.Fatalf("unexpected helm file: %+v", files[0])
	}
	for _, want := range []string{
		"apiVersion: v1",
		"- name: vulnetix",
		`  url: "https://packages.vulnetix.com/helm"`,
		`  username: "org-123"`,
		`  password: "secret"`,
		"  pass_credentials_all: true",
	} {
		if !strings.Contains(files[0].Content, want) {
			t.Errorf("helm config missing %q:\n%s", want, files[0].Content)
		}
	}
}

func TestCargoConfigHasCredentials(t *testing.T) {
	eco, _ := ByCommand("cargo")
	files, err := ConfigFiles(eco, opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("cargo files = %d, want 2 (config + credentials)", len(files))
	}
	if !strings.Contains(files[0].Content, `registry = "sparse+https://packages.vulnetix.com/cargo/"`) {
		t.Errorf("cargo config.toml missing sparse source:\n%s", files[0].Content)
	}
	if files[1].Path != "/home/test/.cargo/credentials.toml" {
		t.Fatalf("cargo creds path = %q", files[1].Path)
	}
	// Basic base64("org-123:secret") == "b3JnLTEyMzpzZWNyZXQ="
	if want := `token = "Basic b3JnLTEyMzpzZWNyZXQ="`; !strings.Contains(files[1].Content, want) {
		t.Errorf("cargo credentials missing %q:\n%s", want, files[1].Content)
	}
}

func TestGemConfigHasAuth(t *testing.T) {
	eco, _ := ByCommand("gem")
	files, err := ConfigFiles(eco, opts())
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://org-123:secret@packages.vulnetix.com/gem/"; !strings.Contains(files[0].Content, want) {
		t.Errorf("gem source missing embedded credentials %q:\n%s", want, files[0].Content)
	}
}

func TestComposerWritesAuthJSON(t *testing.T) {
	eco, _ := ByCommand("composer")
	files, err := ConfigFiles(eco, opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("composer files = %d, want 2 (config.json + auth.json)", len(files))
	}
	// Credentials must live in auth.json, not config.json (composer ignores
	// top-level http-basic in config.json).
	if strings.Contains(files[0].Content, "http-basic") {
		t.Errorf("config.json should not carry credentials:\n%s", files[0].Content)
	}
	if files[1].Path != "/home/test/.composer/auth.json" {
		t.Fatalf("auth path = %q", files[1].Path)
	}
	for _, want := range []string{`"http-basic"`, `"packages.vulnetix.com"`, `"username": "org-123"`, `"password": "secret"`} {
		if !strings.Contains(files[1].Content, want) {
			t.Errorf("auth.json missing %q:\n%s", want, files[1].Content)
		}
	}
}

func TestPubWritesBearerToken(t *testing.T) {
	eco, _ := ByCommand("pub")
	files, err := ConfigFiles(eco, opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("pub files = %d, want 2 (pub.env + pub-tokens.json)", len(files))
	}
	if files[1].Path != "/home/test/.config/dart/pub-tokens.json" {
		t.Fatalf("pub-tokens path = %q", files[1].Path)
	}
	// base64("org-123:secret") == "b3JnLTEyMzpzZWNyZXQ="
	for _, want := range []string{`"url": "https://packages.vulnetix.com/pub"`, `"token": "b3JnLTEyMzpzZWNyZXQ="`} {
		if !strings.Contains(files[1].Content, want) {
			t.Errorf("pub-tokens.json missing %q:\n%s", want, files[1].Content)
		}
	}
}

func TestUnsupportedWriter(t *testing.T) {
	eco, _ := ByCommand("docker")
	if _, err := ConfigFiles(eco, opts()); err == nil {
		t.Fatal("expected unsupported writer error")
	}
}

// TestAURConfig covers the Arch Linux command: paru.conf + yay config.json (both
// merged non-destructively, pointing at the /aur prefix) and a staged pacman
// mirrorlist for the official repos (/arch prefix).
func TestAURConfig(t *testing.T) {
	eco, ok := ByCommand("aur")
	if !ok {
		t.Fatal("ByCommand(aur) not found")
	}
	files, err := ConfigFiles(eco, opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatalf("aur files = %d, want 4 (paru.conf + yay config.json + mirrorlist + pacman.conf)", len(files))
	}

	// paru.conf
	if files[0].Path != "/home/test/.config/paru/paru.conf" {
		t.Fatalf("paru path = %q", files[0].Path)
	}
	if files[0].Merge == nil {
		t.Fatal("paru.conf must be a merge writer")
	}
	paruFromScratch, err := files[0].Merge("")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[options]",
		"AurUrl = https://org-123:secret@packages.vulnetix.com/aur",
		"AurRpcUrl = https://org-123:secret@packages.vulnetix.com/aur/rpc",
	} {
		if !strings.Contains(paruFromScratch, want) {
			t.Errorf("paru.conf missing %q:\n%s", want, paruFromScratch)
		}
	}

	// paru.conf merge into an existing file preserves other settings and replaces
	// a commented-out key in place.
	existing := "[options]\nBottomUp\n#AurUrl = https://aur.archlinux.org\n\n[bin]\nSudo = doas\n"
	merged, err := files[0].Merge(existing)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"BottomUp",
		"[bin]",
		"Sudo = doas",
		"AurUrl = https://org-123:secret@packages.vulnetix.com/aur",
		"AurRpcUrl = https://org-123:secret@packages.vulnetix.com/aur/rpc",
	} {
		if !strings.Contains(merged, want) {
			t.Errorf("merged paru.conf missing %q:\n%s", want, merged)
		}
	}
	if strings.Contains(merged, "#AurUrl") {
		t.Errorf("merged paru.conf should replace the commented AurUrl:\n%s", merged)
	}

	// yay config.json
	if files[1].Path != "/home/test/.config/yay/config.json" {
		t.Fatalf("yay path = %q", files[1].Path)
	}
	if files[1].Merge == nil {
		t.Fatal("yay config.json must be a merge writer")
	}
	yayMerged, err := files[1].Merge(`{"buildDir":"/tmp/yay","cleanAfter":true}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"buildDir": "/tmp/yay"`,
		`"aururl": "https://org-123:secret@packages.vulnetix.com/aur"`,
		`"aurrpcurl": "https://org-123:secret@packages.vulnetix.com/aur/rpc"`,
	} {
		if !strings.Contains(yayMerged, want) {
			t.Errorf("merged yay config missing %q:\n%s", want, yayMerged)
		}
	}

	// staged pacman mirrorlist (official repos via /arch)
	if files[2].Path != "/home/test/.config/vulnetix/package-firewall/arch-mirrorlist" {
		t.Fatalf("mirrorlist path = %q", files[2].Path)
	}
	want := "Server = https://org-123:secret@packages.vulnetix.com/arch/$repo/os/$arch"
	if !strings.Contains(files[2].Content, want) {
		t.Errorf("mirrorlist missing %q:\n%s", want, files[2].Content)
	}

	// complete pacman.conf (official repos via /arch)
	if files[3].Path != "/home/test/.config/vulnetix/package-firewall/pacman.conf" {
		t.Fatalf("pacman.conf path = %q", files[3].Path)
	}
	for _, want := range []string{
		"[core]", "[extra]", "[multilib]",
		"Server = https://org-123:secret@packages.vulnetix.com/arch/$repo/os/$arch",
	} {
		if !strings.Contains(files[3].Content, want) {
			t.Errorf("pacman.conf missing %q:\n%s", want, files[3].Content)
		}
	}
}
