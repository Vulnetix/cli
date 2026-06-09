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
	if want := `export HEX_MIRROR="https://packages.vulnetix.com/hex"`; !strings.Contains(files[0].Content, want) {
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
		`options(repos = c(CRAN = "https://packages.vulnetix.com/cran"))`,
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

func TestUnsupportedWriter(t *testing.T) {
	eco, _ := ByCommand("docker")
	if _, err := ConfigFiles(eco, opts()); err == nil {
		t.Fatal("expected unsupported writer error")
	}
}
